/**
 * Reviewed copy of `parc-contracts/security/scopes.v1.json` (version 1).
 * Auth enforces this policy when issuing service and delegated tokens. Update
 * it only together with the contract.
 */
export interface ScopeDefinition {
  audience: string;
  description: string;
  service: boolean;
  platform?: boolean;
  delegated: { CUSTOMER?: true; ADMINISTRATOR?: true | string };
}

export interface ScopeCatalogue {
  version: number;
  scopes: Record<string, ScopeDefinition>;
  clients: Record<string, { service: string[]; delegated: string[] }>;
}

export const scopeCatalogue: ScopeCatalogue = {
  version: 1,
  scopes: {
    "auth.administrator-authentication": {
      audience: "parc-auth-customer",
      description:
        "Administrator credential, MFA and passkey ceremonies on behalf of the Admin BFF.",
      service: true,
      delegated: {},
      platform: true,
    },
    "auth.lending-eligibility.read": {
      audience: "parc-auth-customer",
      description: "Read a customer's consented lending-eligibility evidence.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "auth.tokens.introspect": {
      audience: "parc-auth-customer",
      description:
        "Introspect a user access token (legacy; prefer local JWT validation).",
      service: true,
      delegated: {},
    },
    "auth.transaction-authorizations.consume": {
      audience: "parc-auth-customer",
      description: "Consume a customer's single-use transaction authorization.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "ledger.accounts.provision": {
      audience: "parc-ledger",
      description: "Provision customer and tenant ledger accounts.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "ledger.adjustments.write": {
      audience: "parc-ledger",
      description: "Post an approval-bound manual adjustment.",
      service: false,
      delegated: {
        ADMINISTRATOR: "ledger.adjustment.post",
      },
    },
    "ledger.balances.read": {
      audience: "parc-ledger",
      description: "Read account and customer wallet balances.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "ledger.postings.write": {
      audience: "parc-ledger",
      description:
        "Post balanced journals and create, release or capture holds.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "ledger.reversals.write": {
      audience: "parc-ledger",
      description:
        "Reverse a posted transaction under an approval or automated rule.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "ledger.statements": {
      audience: "parc-ledger",
      description: "Request and read the customer's own statements.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "lending.customer.read": {
      audience: "parc-lending",
      description:
        "Read the customer's own loan products, quotes, applications, offers and loans.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "lending.customer.write": {
      audience: "parc-lending",
      description: "Apply, accept offers and repay as the customer.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "lending.loans.manage": {
      audience: "parc-lending",
      description: "Restructure and write off loans.",
      service: false,
      delegated: {
        ADMINISTRATOR: "lending.loan.manage",
      },
    },
    "lending.products.manage": {
      audience: "parc-lending",
      description: "Create, version and publish loan products.",
      service: false,
      delegated: {
        ADMINISTRATOR: "lending.product.manage",
      },
    },
    "lending.servicing.process": {
      audience: "parc-lending",
      description:
        "Evaluate applications, disburse, and record or reverse repayments and recoveries.",
      service: true,
      delegated: {
        ADMINISTRATOR: "lending.servicing.process",
      },
    },
    "lending.underwriting.manage": {
      audience: "parc-lending",
      description: "Manual review, decisions and offers.",
      service: false,
      delegated: {
        ADMINISTRATOR: "lending.underwriting.manage",
      },
    },
    "payment.bill-catalogue.manage": {
      audience: "parc-payment",
      description: "Import and publish the tenant bill catalogue.",
      service: false,
      delegated: {
        ADMINISTRATOR: "payment.bill-catalogue.manage",
      },
    },
    "payment.collections.write": {
      audience: "parc-payment",
      description: "Request a collection on behalf of a domain service.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "payment.customer.read": {
      audience: "parc-payment",
      description:
        "Read the customer's own payments, transfers, bills and beneficiaries.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "payment.customer.write": {
      audience: "parc-payment",
      description:
        "Initiate the customer's own payments, transfers, bills and beneficiaries.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "payment.payouts.write": {
      audience: "parc-payment",
      description: "Request a payout on behalf of a domain service.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "savings.customer.read": {
      audience: "parc-savings",
      description: "Read the customer's own savings, quotes and deposits.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "savings.customer.write": {
      audience: "parc-savings",
      description:
        "Open accounts, contribute, withdraw and manage deposits and plans as the customer.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "savings.operations.process": {
      audience: "parc-savings",
      description:
        "Accrue and pay interest, execute recurring plans and mature deposits.",
      service: true,
      delegated: {
        ADMINISTRATOR: "savings.operations.process",
      },
    },
    "savings.products.manage": {
      audience: "parc-savings",
      description: "Create savings products and versions.",
      service: false,
      delegated: {
        ADMINISTRATOR: "savings.product.manage",
      },
    },
    "savings.products.publish": {
      audience: "parc-savings",
      description: "Publish an approved savings product version.",
      service: false,
      delegated: {
        ADMINISTRATOR: "savings.product.publish",
      },
    },
    "tenant.administration": {
      audience: "parc-tenant-admin",
      description:
        "Administrator console operations; Tenant Admin enforces the fine-grained permission per route.",
      service: false,
      delegated: {
        ADMINISTRATOR: true,
      },
      platform: true,
    },
    "tenant.administrators.authenticate": {
      audience: "parc-tenant-admin",
      description:
        "Verify administrator credentials and read administrator authorization and authentication policy.",
      service: true,
      delegated: {},
      platform: true,
    },
    "tenant.approvals.consume": {
      audience: "parc-tenant-admin",
      description:
        "Consume and report execution of a decided maker-checker approval.",
      service: true,
      delegated: {
        ADMINISTRATOR: true,
      },
      platform: true,
    },
    "tenant.configuration.read": {
      audience: "parc-tenant-admin",
      description: "Read published tenant configuration.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "tenant.consent-documents.validate": {
      audience: "parc-tenant-admin",
      description: "Validate consent documents presented at registration.",
      service: true,
      delegated: {},
    },
    "tenant.customer-support.read": {
      audience: "parc-tenant-admin",
      description: "Read the customer's own support FAQs and tickets.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "tenant.customer-support.write": {
      audience: "parc-tenant-admin",
      description: "Open support tickets for the customer.",
      service: false,
      delegated: {
        CUSTOMER: true,
      },
    },
    "tenant.mobile-bootstrap.read": {
      audience: "parc-tenant-admin",
      description:
        "Resolve pre-login mobile bootstrap configuration by tenant slug (no tenant context yet).",
      service: true,
      delegated: {},
      platform: true,
    },
    "tenant.onboarding-reference.read": {
      audience: "parc-tenant-admin",
      description: "Read pre-login onboarding reference data.",
      service: true,
      delegated: {},
    },
    "tenant.provider-selection.read": {
      audience: "parc-tenant-admin",
      description: "Resolve the tenant's selected provider for a capability.",
      service: true,
      delegated: {
        CUSTOMER: true,
        ADMINISTRATOR: true,
      },
    },
    "tenant.status.read": {
      audience: "parc-tenant-admin",
      description: "Read tenant lifecycle status.",
      service: true,
      delegated: {},
    },
  },
  clients: {
    "parc-admin-bff": {
      service: ["auth.administrator-authentication"],
      delegated: [
        "ledger.adjustments.write",
        "ledger.balances.read",
        "lending.loans.manage",
        "lending.products.manage",
        "lending.servicing.process",
        "lending.underwriting.manage",
        "payment.bill-catalogue.manage",
        "savings.operations.process",
        "savings.products.manage",
        "savings.products.publish",
        "tenant.administration",
      ],
    },
    "parc-auth-customer": {
      service: [
        "tenant.administrators.authenticate",
        "tenant.approvals.consume",
        "tenant.consent-documents.validate",
        "tenant.status.read",
      ],
      delegated: [],
    },
    "parc-ledger": {
      service: ["tenant.approvals.consume"],
      delegated: ["tenant.approvals.consume"],
    },
    "parc-lending": {
      service: [
        "auth.lending-eligibility.read",
        "ledger.postings.write",
        "ledger.reversals.write",
        "payment.collections.write",
        "payment.payouts.write",
        "tenant.approvals.consume",
      ],
      delegated: [
        "auth.lending-eligibility.read",
        "auth.transaction-authorizations.consume",
        "ledger.postings.write",
        "ledger.reversals.write",
        "payment.collections.write",
        "payment.payouts.write",
        "tenant.approvals.consume",
      ],
    },
    "parc-mobile-bff": {
      service: [
        "tenant.mobile-bootstrap.read",
        "tenant.onboarding-reference.read",
      ],
      delegated: [
        "ledger.balances.read",
        "ledger.statements",
        "lending.customer.read",
        "lending.customer.write",
        "payment.customer.read",
        "payment.customer.write",
        "savings.customer.read",
        "savings.customer.write",
        "tenant.customer-support.read",
        "tenant.customer-support.write",
      ],
    },
    "parc-payment": {
      service: [
        "ledger.accounts.provision",
        "ledger.balances.read",
        "ledger.postings.write",
        "ledger.reversals.write",
        "tenant.approvals.consume",
        "tenant.configuration.read",
        "tenant.provider-selection.read",
      ],
      delegated: [
        "ledger.accounts.provision",
        "ledger.balances.read",
        "ledger.postings.write",
        "ledger.reversals.write",
        "tenant.approvals.consume",
        "tenant.configuration.read",
        "tenant.provider-selection.read",
      ],
    },
    "parc-savings": {
      service: [
        "ledger.accounts.provision",
        "ledger.balances.read",
        "ledger.postings.write",
        "tenant.approvals.consume",
      ],
      delegated: [
        "ledger.accounts.provision",
        "ledger.balances.read",
        "ledger.postings.write",
        "tenant.approvals.consume",
      ],
    },
    "parc-tenant-admin": {
      service: [],
      delegated: [],
    },
  },
};
