import { z } from "zod";
import {
  unsupportedFaceEvidence,
  type FaceEvidence,
  type FaceVerificationProvider,
  type IdentityVerificationProvider,
  type KycIdentityType,
  type KycProviderResult,
  type VerifiedIdentityAttributes,
} from "./kyc-provider.js";

const paths = {
  ninBasic: "/verification/vnin-basic",
  bvnBasic: "/verification/bvn_validation",
  liveness: "/verification/biometrics/face/liveliness_check",
  ninWithFace: "/verification/nin_w_face",
  bvnWithFace: "/verification/bvn_w_face",
} as const;

const callLabels: Record<string, string> = {
  [paths.ninBasic]: "NIN lookup",
  [paths.bvnBasic]: "BVN lookup",
  [paths.liveness]: "Liveness check",
  [paths.ninWithFace]: "NIN face match",
  [paths.bvnWithFace]: "BVN face match",
};

const ninDataSchema = z
  .object({
    nin: z.string().optional(),
    firstname: z.string().optional(),
    middlename: z.string().optional(),
    surname: z.string().optional(),
    birthdate: z.string().optional(),
    nin_suspension_status: z.boolean().optional(),
  })
  .passthrough();

// BVN records come back camelCase (firstName, dateOfBirth "01-Jan-2000").
const bvnDataSchema = z
  .object({
    bvn: z.string().optional(),
    number: z.string().optional(),
    firstName: z.string().optional(),
    middleName: z.string().optional(),
    lastName: z.string().optional(),
    dateOfBirth: z.string().optional(),
  })
  .passthrough();

const faceDataSchema = z
  .object({
    status: z.boolean().optional(),
    confidence: z.number().optional(),
  })
  .passthrough();

// The documented shape keeps nin_data/face_data at the top level; the API
// also returns them inside `data` (NIN Basic puts the record in `data` itself).
const responseSchema = z
  .object({
    status: z.boolean().optional(),
    response_code: z.string().optional(),
    reference_id: z.string().optional(),
    is_sandbox: z.boolean().optional(),
    verification: z
      .object({ reference: z.string().optional() })
      .passthrough()
      .optional(),
    nin_data: ninDataSchema.optional(),
    face_data: faceDataSchema.optional(),
    data: ninDataSchema
      .merge(bvnDataSchema)
      .extend({
        confidence: z.number().optional(),
        confidence_in_percentage: z.number().optional(),
        nin_data: ninDataSchema.optional(),
        face_data: faceDataSchema.optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

type PremblyResponse = z.infer<typeof responseSchema>;

type PremblyCall =
  | { kind: "RESPONSE"; httpStatus: number; body: PremblyResponse }
  | { kind: "UNKNOWN"; resultCode: string };

export interface PremblyProviderOptions {
  baseUrl: string;
  apiKey: string;
  appId?: string;
  configurationVersion: string;
  timeoutMs: number;
  /** Face-match confidence Prembly must reach, 70-100. */
  faceMatchThreshold: number;
  /** Minimum liveness confidence, as a percentage. */
  livenessMinimumPercent: number;
  /**
   * Accept sandbox responses, whose canned record never matches the NIN sent.
   * Off outside development so a test key can never verify a real customer.
   */
  allowSandbox: boolean;
  /**
   * Development only: print every Prembly call to the console with the NIN
   * masked and images trimmed. The config refuses it in production.
   */
  debugLog?: boolean;
  fetchImplementation?: typeof fetch;
}

function displayName(value?: string): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  return trimmed
    .toLowerCase()
    .replace(
      /(^|[\s'-])([a-z])/g,
      (_match, separator: string, letter: string) =>
        `${separator}${letter.toUpperCase()}`,
    );
}

const monthNumbers: Record<string, string> = {
  jan: "01",
  feb: "02",
  mar: "03",
  apr: "04",
  may: "05",
  jun: "06",
  jul: "07",
  aug: "08",
  sep: "09",
  oct: "10",
  nov: "11",
  dec: "12",
};

/**
 * Accepts YYYY-MM-DD, DD-MM-YYYY, DD/MM/YYYY and the BVN register's
 * DD-Mon-YYYY ("01-Jan-2000"); anything else is dropped.
 */
function isoDate(value?: string): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  const iso = /^(\d{4})-(\d{2})-(\d{2})$/.exec(trimmed);
  const dayFirst = /^(\d{2})[-/](\d{2})[-/](\d{4})$/.exec(trimmed);
  const monthName = /^(\d{2})-([A-Za-z]{3})-(\d{4})$/.exec(trimmed);
  const namedMonth = monthName?.[2]
    ? monthNumbers[monthName[2].toLowerCase()]
    : undefined;
  const [year, month, day] = iso
    ? [iso[1], iso[2], iso[3]]
    : dayFirst
      ? [dayFirst[3], dayFirst[2], dayFirst[1]]
      : monthName && namedMonth
        ? [monthName[3], namedMonth, monthName[1]]
        : [];
  if (!year || !month || !day) return undefined;
  const candidate = `${year}-${month}-${day}`;
  const parsed = new Date(`${candidate}T00:00:00Z`);
  return Number.isNaN(parsed.getTime()) ||
    parsed.toISOString().slice(0, 10) !== candidate
    ? undefined
    : candidate;
}

const maskedKeys =
  /^(nin|bvn|number|vnin|identity_value|telephoneno|phone.*)$/i;

function maskValue(value: string): string {
  return value.length <= 4
    ? "****"
    : `${"*".repeat(value.length - 4)}${value.slice(-4)}`;
}

/** Masks identifiers and swaps base64 images for their size so the log stays readable. */
function debugSafe(value: unknown, key = ""): unknown {
  if (typeof value === "string") {
    if (maskedKeys.test(key)) return maskValue(value);
    if (value.length > 200 && /^[A-Za-z0-9+/=\s]+$/.test(value.slice(0, 200)))
      return `[base64, ${(value.length / 1024).toFixed(1)} KB]`;
    return value;
  }
  if (typeof value === "number" && maskedKeys.test(key))
    return maskValue(String(value));
  if (Array.isArray(value)) return value.map((item) => debugSafe(item, key));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entry]) => [
        entryKey,
        debugSafe(entry, entryKey),
      ]),
    );
  return value;
}

function indent(text: string): string {
  return text
    .split("\n")
    .map((line) => `│   ${line}`)
    .join("\n");
}

function succeeded(body: PremblyResponse): boolean {
  return body.status === true && body.response_code === "00";
}

/** The registered record, normalised across the NIN (snake) and BVN (camel) shapes. */
interface RegisteredRecord {
  number?: string | undefined;
  firstName?: string | undefined;
  middleName?: string | undefined;
  lastName?: string | undefined;
  birthdate?: string | undefined;
  suspended?: boolean | undefined;
}

function ninRecord(body: PremblyResponse): RegisteredRecord | undefined {
  const record =
    body.nin_data ??
    body.data?.nin_data ??
    (body.data?.firstname || body.data?.surname ? body.data : undefined);
  return record
    ? {
        number: record.nin,
        firstName: record.firstname,
        middleName: record.middlename,
        lastName: record.surname,
        birthdate: record.birthdate,
        suspended: record.nin_suspension_status,
      }
    : undefined;
}

function bvnRecord(body: PremblyResponse): RegisteredRecord | undefined {
  const record = body.data;
  return record?.firstName || record?.lastName
    ? {
        number: record.bvn ?? record.number,
        firstName: record.firstName,
        middleName: record.middleName,
        lastName: record.lastName,
        birthdate: record.dateOfBirth,
      }
    : undefined;
}

function registeredRecord(
  identityType: KycIdentityType,
  body: PremblyResponse,
): RegisteredRecord | undefined {
  return identityType === "BVN" ? bvnRecord(body) : ninRecord(body);
}

function faceData(body: PremblyResponse) {
  return body.face_data ?? body.data?.face_data;
}

export class PremblyProvider
  implements IdentityVerificationProvider, FaceVerificationProvider
{
  public readonly name = "PREMBLY" as const;
  private readonly fetchImplementation: typeof fetch;

  public constructor(private readonly options: PremblyProviderOptions) {
    this.fetchImplementation = options.fetchImplementation ?? fetch;
  }

  public async verifyIdentity(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
  }): Promise<KycProviderResult> {
    const fallbackReference = `prembly-request:${input.verificationId}`;
    const call = await this.call(
      input.identityType === "BVN" ? paths.bvnBasic : paths.ninBasic,
      input.verificationId,
      { number: input.identityValue },
    );
    if (call.kind === "UNKNOWN") return this.pending(fallbackReference, call);
    const { body } = call;
    const reference = this.reference(body, fallbackReference);
    const rejected = this.rejection(call, reference);
    if (rejected) return rejected;
    const record = registeredRecord(input.identityType, body);
    if (
      !body.is_sandbox &&
      record?.number &&
      record.number !== input.identityValue
    )
      return this.result("MANUAL_REVIEW", reference, "IDENTITY_MISMATCH", {
        status: "manual_review",
      });
    if (record?.suspended === true)
      return this.result("MANUAL_REVIEW", reference, "NIN_SUSPENDED", {
        status: "manual_review",
      });
    const attributes: VerifiedIdentityAttributes = {};
    const firstName = displayName(record?.firstName);
    const middleName = displayName(record?.middleName);
    const lastName = displayName(record?.lastName);
    const dateOfBirth = isoDate(record?.birthdate);
    if (firstName) attributes.firstName = firstName;
    if (middleName) attributes.middleName = middleName;
    if (lastName) attributes.lastName = lastName;
    if (dateOfBirth) attributes.dateOfBirth = dateOfBirth;
    if (!firstName || !lastName)
      return this.result(
        "MANUAL_REVIEW",
        reference,
        "IDENTITY_DATA_INCOMPLETE",
        { status: "manual_review" },
      );
    return {
      ...this.result("VERIFIED", reference, "SUCCESS", { status: "success" }),
      identityAttributes: attributes,
    };
  }

  public async verifyFace(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
    evidence: FaceEvidence;
  }): Promise<KycProviderResult> {
    const fallbackReference = `prembly-biometric:${input.verificationId}`;
    if (input.evidence.kind !== "SELFIE_IMAGE")
      return unsupportedFaceEvidence(
        fallbackReference,
        this.options.configurationVersion,
      );
    const image = input.evidence.imageBase64;

    const liveness = await this.call(paths.liveness, input.verificationId, {
      image,
    });
    if (liveness.kind === "UNKNOWN")
      return this.pending(fallbackReference, liveness);
    const livenessRejected = this.rejection(
      liveness,
      this.reference(liveness.body, fallbackReference),
    );
    if (livenessRejected?.outcome === "PENDING") return livenessRejected;
    const livenessPercent = this.livenessPercent(liveness.body);
    if (
      livenessRejected ||
      livenessPercent === undefined ||
      livenessPercent < this.options.livenessMinimumPercent
    )
      return this.result(
        "FAILED",
        this.reference(liveness.body, fallbackReference),
        "LIVENESS_NOT_DETECTED",
        {
          status: "failed",
          liveness_verified: false,
          face_matched: false,
        },
      );

    const match = await this.call(
      input.identityType === "BVN" ? paths.bvnWithFace : paths.ninWithFace,
      input.verificationId,
      {
        number: input.identityValue,
        image,
        face_confidence_threshold: this.options.faceMatchThreshold,
      },
    );
    if (match.kind === "UNKNOWN") return this.pending(fallbackReference, match);
    const reference = this.reference(match.body, fallbackReference);
    const matchRejected = this.rejection(match, reference);
    if (matchRejected?.outcome === "PENDING") return matchRejected;
    const record = registeredRecord(input.identityType, match.body);
    const matchedRecord =
      match.body.is_sandbox === true || record?.number === input.identityValue;
    const faceMatched =
      !matchRejected && faceData(match.body)?.status === true && matchedRecord;
    return this.result(
      faceMatched ? "VERIFIED" : "FAILED",
      reference,
      faceMatched ? "LIVENESS_AND_FACE_MATCHED" : "FACE_NOT_MATCHED",
      {
        status: faceMatched ? "success" : "failed",
        liveness_verified: true,
        face_matched: faceMatched,
      },
    );
  }

  private async call(
    path: string,
    verificationId: string,
    body: Record<string, unknown>,
  ): Promise<PremblyCall> {
    const startedAt = Date.now();
    try {
      const response = await this.fetchImplementation(
        `${this.options.baseUrl}${path}`,
        {
          method: "POST",
          headers: {
            accept: "application/json",
            "content-type": "application/json",
            "x-api-key": this.options.apiKey,
            ...(this.options.appId ? { "app-id": this.options.appId } : {}),
            "x-correlation-id": verificationId,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(this.options.timeoutMs),
        },
      );
      const raw: unknown = await response.json().catch(() => ({}));
      this.debugCall(path, verificationId, body, {
        httpStatus: response.status,
        durationMs: Date.now() - startedAt,
        response: raw,
      });
      const parsed = responseSchema.safeParse(raw);
      if (
        parsed.success &&
        parsed.data.is_sandbox &&
        !this.options.allowSandbox
      )
        return { kind: "UNKNOWN", resultCode: "PROVIDER_SANDBOX_RESPONSE" };
      return {
        kind: "RESPONSE",
        httpStatus: response.status,
        body: parsed.success ? parsed.data : {},
      };
    } catch (error) {
      this.debugCall(path, verificationId, body, {
        durationMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      });
      return { kind: "UNKNOWN", resultCode: "PROVIDER_OUTCOME_UNKNOWN" };
    }
  }

  private debugCall(
    path: string,
    verificationId: string,
    request: Record<string, unknown>,
    outcome:
      | { httpStatus: number; durationMs: number; response: unknown }
      | { durationMs: number; error: string },
  ): void {
    if (!this.options.debugLog) return;
    const label = callLabels[path] ?? path;
    const rule = "─".repeat(Math.max(4, 60 - label.length));
    const lines = [
      "",
      `┌─ Prembly · ${label} ${rule}`,
      `│ POST ${path}`,
      `│ verification  ${verificationId}`,
    ];
    if ("error" in outcome) {
      lines.push(
        `│ ✖ request failed after ${String(outcome.durationMs)} ms: ${outcome.error}`,
      );
    } else {
      const response = (outcome.response ?? {}) as Record<string, unknown>;
      const field = (name: string) =>
        response[name] === undefined ? "—" : JSON.stringify(response[name]);
      const summary = [
        `status ${field("status")}`,
        `response_code ${field("response_code")}`,
        `sandbox ${field("is_sandbox")}`,
      ].join(" · ");
      lines.push(
        `│ HTTP ${String(outcome.httpStatus)} · ${String(outcome.durationMs)} ms`,
        `│ ${summary}`,
        "├─ request",
        indent(JSON.stringify(debugSafe(request), null, 2)),
        "├─ response",
        indent(JSON.stringify(debugSafe(response), null, 2)),
      );
    }
    lines.push(`└${"─".repeat(64 + 10)}`);
    console.log(lines.join("\n"));
  }

  /**
   * Undefined when Prembly answered successfully. A definitive "no" is FAILED;
   * auth, billing, throttling and server errors stay PENDING because the
   * identity itself was never checked.
   */
  private rejection(
    call: Extract<PremblyCall, { kind: "RESPONSE" }>,
    reference: string,
  ): KycProviderResult | undefined {
    if (call.httpStatus >= 200 && call.httpStatus < 300 && succeeded(call.body))
      return undefined;
    const definitive =
      (call.httpStatus >= 200 && call.httpStatus < 300) ||
      call.httpStatus === 400 ||
      call.httpStatus === 404 ||
      call.httpStatus === 422;
    if (!definitive)
      return this.pending(reference, {
        kind: "UNKNOWN",
        resultCode: `HTTP_${String(call.httpStatus)}`,
      });
    return this.result(
      "FAILED",
      reference,
      call.body.response_code
        ? `PREMBLY_${call.body.response_code}`
        : `HTTP_${String(call.httpStatus)}`,
      { status: "failed" },
    );
  }

  private livenessPercent(body: PremblyResponse): number | undefined {
    if (body.data?.confidence_in_percentage !== undefined)
      return body.data.confidence_in_percentage;
    const confidence = body.data?.confidence;
    if (confidence === undefined) return undefined;
    return confidence <= 1 ? confidence * 100 : confidence;
  }

  private reference(body: PremblyResponse, fallback: string): string {
    return body.verification?.reference ?? body.reference_id ?? fallback;
  }

  private pending(
    providerReference: string,
    call: Extract<PremblyCall, { kind: "UNKNOWN" }>,
  ): KycProviderResult {
    return this.result("PENDING", providerReference, call.resultCode, {
      status: "pending",
    });
  }

  private result(
    outcome: KycProviderResult["outcome"],
    providerReference: string,
    resultCode: string,
    safeResult: Record<string, unknown>,
  ): KycProviderResult {
    if (this.options.debugLog)
      console.log(
        `  ↳ Prembly decision: ${outcome} · ${resultCode} · ref ${providerReference}\n`,
      );
    return {
      outcome,
      providerReference,
      providerConfigurationVersion: this.options.configurationVersion,
      resultCode,
      safeResult,
    };
  }
}
