--
-- PostgreSQL database dump
--

-- Dumped from database version 14.18 (Homebrew)
-- Dumped by pg_dump version 14.18 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: aml_check_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.aml_check_status AS ENUM (
    'PENDING',
    'CLEAR',
    'MATCH',
    'REVIEW_REQUIRED',
    'FAILED',
    'ERROR'
);


--
-- Name: aml_risk_level; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.aml_risk_level AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);


--
-- Name: biometric_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.biometric_type AS ENUM (
    'FACE',
    'FINGERPRINT',
    'PASSKEY'
);


--
-- Name: consent_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.consent_type AS ENUM (
    'TERMS_AND_CONDITIONS',
    'PRIVACY_POLICY',
    'DATA_PROCESSING',
    'KYC',
    'CREDIT_CHECK',
    'MARKETING',
    'BIOMETRIC',
    'OPEN_BANKING',
    'DIRECT_DEBIT'
);


--
-- Name: credential_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.credential_type AS ENUM (
    'PASSWORD',
    'PIN',
    'PASSKEY'
);


--
-- Name: device_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.device_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'BLOCKED'
);


--
-- Name: fraud_flag_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.fraud_flag_status AS ENUM (
    'FLAGGED',
    'UNDER_REVIEW',
    'CLEARED',
    'BLOCKED'
);


--
-- Name: fraud_severity; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.fraud_severity AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);


--
-- Name: kyc_document_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.kyc_document_type AS ENUM (
    'NIN',
    'BVN',
    'INTERNATIONAL_PASSPORT',
    'DRIVERS_LICENSE',
    'VOTERS_CARD',
    'CAC_CERTIFICATE',
    'UTILITY_BILL',
    'BANK_STATEMENT',
    'PROOF_OF_ADDRESS',
    'OTHER'
);


--
-- Name: kyc_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.kyc_status AS ENUM (
    'NOT_STARTED',
    'PENDING',
    'IN_PROGRESS',
    'VERIFIED',
    'REJECTED',
    'EXPIRED',
    'REQUIRES_REVIEW'
);


--
-- Name: notification_channel; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.notification_channel AS ENUM (
    'PUSH',
    'SMS',
    'EMAIL',
    'IN_APP'
);


--
-- Name: notification_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.notification_status AS ENUM (
    'PENDING',
    'QUEUED',
    'SENT',
    'DELIVERED',
    'READ',
    'FAILED',
    'CANCELLED'
);


--
-- Name: otp_purpose; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.otp_purpose AS ENUM (
    'SIGNUP',
    'LOGIN',
    'TRANSACTION',
    'PASSWORD_RESET',
    'PIN_RESET',
    'PHONE_VERIFICATION',
    'EMAIL_VERIFICATION',
    'DEVICE_VERIFICATION',
    'KYC_VERIFICATION'
);


--
-- Name: referral_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.referral_status AS ENUM (
    'PENDING',
    'QUALIFIED',
    'REWARDED',
    'EXPIRED',
    'CANCELLED'
);


--
-- Name: reward_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.reward_status AS ENUM (
    'PENDING',
    'APPROVED',
    'PROCESSING',
    'PAID',
    'REVERSED',
    'CANCELLED'
);


--
-- Name: two_fa_method_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.two_fa_method_type AS ENUM (
    'SMS',
    'EMAIL',
    'AUTHENTICATOR',
    'PASSKEY'
);


--
-- Name: user_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.user_status AS ENUM (
    'PENDING',
    'ACTIVE',
    'SUSPENDED',
    'BLOCKED',
    'DEACTIVATED'
);


--
-- Name: user_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.user_type AS ENUM (
    'CUSTOMER',
    'STAFF',
    'SERVICE_ACCOUNT'
);


--
-- Name: verification_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.verification_type AS ENUM (
    'NIN',
    'BVN',
    'DOCUMENT',
    'ADDRESS',
    'PHONE',
    'EMAIL',
    'BIOMETRIC',
    'PEP',
    'SANCTIONS'
);


--
-- Name: enforce_parent_tenant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_parent_tenant() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    parent_tenant UUID;
    parent_id UUID;
BEGIN
    parent_id := (to_jsonb(NEW) ->> TG_ARGV[2])::uuid;
    IF parent_id IS NULL THEN
        RETURN NEW;
    END IF;

    EXECUTE format('SELECT tenant_id FROM %I WHERE id = $1', TG_ARGV[0])
       INTO parent_tenant
       USING parent_id;

    IF parent_tenant IS NULL THEN
        RAISE EXCEPTION 'Referenced % record does not exist', TG_ARGV[0]
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM parent_tenant THEN
        RAISE EXCEPTION 'Cross-tenant reference rejected on %.%', TG_TABLE_NAME, TG_ARGV[2]
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$_$;


--
-- Name: prevent_published_record_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_published_record_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN IF OLD.status = 'PUBLISHED' THEN RAISE EXCEPTION 'Published records are immutable'; END IF; RETURN NEW; END $$;


--
-- Name: reject_auth_audit_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_auth_audit_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN RAISE EXCEPTION 'Auth audit events are append-only'; END $$;


--
-- Name: reject_completed_notification_attempt_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_completed_notification_attempt_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      IF OLD.status <> 'PROCESSING' AND NOT (
        current_setting('app.retention_maintenance', true) = 'true' AND
        OLD.legal_hold = false AND
        OLD.metadata_retain_until <= now() AND
        (TG_OP = 'DELETE' OR (
          NEW.id = OLD.id AND NEW.tenant_id = OLD.tenant_id AND
          NEW.notification_id = OLD.notification_id AND NEW.status = OLD.status AND
          NEW.provider_reference IS NULL AND NEW.failure_code IS NULL AND
          NEW.response_metadata = '{}'::jsonb
        ))
      ) THEN
        RAISE EXCEPTION 'Completed notification delivery attempts are append-only';
      END IF;
      IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
      RETURN NEW;
    END $$;


--
-- Name: set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: account_recovery_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_recovery_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    reason character varying(100),
    status character varying(30) DEFAULT 'PENDING'::character varying NOT NULL,
    requested_by_identifier character varying(255),
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    resolution_notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.account_recovery_requests FORCE ROW LEVEL SECURITY;


--
-- Name: aml_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.aml_profiles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    risk_level public.aml_risk_level DEFAULT 'LOW'::public.aml_risk_level NOT NULL,
    risk_score numeric(5,2),
    pep_status boolean DEFAULT false NOT NULL,
    sanctions_status boolean DEFAULT false NOT NULL,
    adverse_media_status boolean DEFAULT false NOT NULL,
    last_screened_at timestamp with time zone,
    next_screening_at timestamp with time zone,
    enhanced_due_diligence_required boolean DEFAULT false NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    CONSTRAINT aml_risk_score_chk CHECK (((risk_score IS NULL) OR ((risk_score >= (0)::numeric) AND (risk_score <= (100)::numeric))))
);

ALTER TABLE ONLY public.aml_profiles FORCE ROW LEVEL SECURITY;


--
-- Name: aml_screening_checks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.aml_screening_checks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    check_type public.verification_type NOT NULL,
    provider_name character varying(100) NOT NULL,
    provider_reference character varying(255),
    status public.aml_check_status DEFAULT 'PENDING'::public.aml_check_status NOT NULL,
    initiated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    provider_configuration_version character varying(100)
);

ALTER TABLE ONLY public.aml_screening_checks FORCE ROW LEVEL SECURITY;


--
-- Name: aml_screening_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.aml_screening_results (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    screening_check_id uuid NOT NULL,
    match_found boolean DEFAULT false NOT NULL,
    match_score numeric(5,2),
    matched_name text,
    matched_list character varying(255),
    result_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT aml_match_score_chk CHECK (((match_score IS NULL) OR ((match_score >= (0)::numeric) AND (match_score <= (100)::numeric))))
);

ALTER TABLE ONLY public.aml_screening_results FORCE ROW LEVEL SECURITY;


--
-- Name: auth_audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_audit_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    actor_id uuid,
    actor_type character varying(50) NOT NULL,
    event_type character varying(150) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    outcome character varying(30) NOT NULL,
    reason text,
    ip_address inet,
    user_agent text,
    correlation_id uuid,
    request_id character varying(150),
    previous_values jsonb,
    new_values jsonb,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    retain_until timestamp with time zone,
    legal_hold boolean DEFAULT false NOT NULL,
    CONSTRAINT audit_outcome_chk CHECK (((outcome)::text = ANY (ARRAY[('SUCCESS'::character varying)::text, ('FAILURE'::character varying)::text, ('DENIED'::character varying)::text, ('ERROR'::character varying)::text])))
);

ALTER TABLE ONLY public.auth_audit_events FORCE ROW LEVEL SECURITY;


--
-- Name: auth_customer_inbox_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_customer_inbox_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type character varying(150) NOT NULL,
    source_service character varying(100) NOT NULL,
    aggregate_type character varying(100),
    aggregate_id uuid,
    payload jsonb NOT NULL,
    headers jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(30) DEFAULT 'RECEIVED'::character varying NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    next_retry_at timestamp with time zone,
    last_error text,
    CONSTRAINT inbox_retry_chk CHECK ((retry_count >= 0)),
    CONSTRAINT inbox_status_chk CHECK (((status)::text = ANY (ARRAY[('RECEIVED'::character varying)::text, ('PROCESSING'::character varying)::text, ('PROCESSED'::character varying)::text, ('FAILED'::character varying)::text, ('DEAD_LETTER'::character varying)::text])))
);

ALTER TABLE ONLY public.auth_customer_inbox_events FORCE ROW LEVEL SECURITY;


--
-- Name: auth_customer_outbox_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_customer_outbox_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type character varying(150) NOT NULL,
    aggregate_type character varying(100) NOT NULL,
    aggregate_id uuid NOT NULL,
    payload jsonb NOT NULL,
    headers jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(30) DEFAULT 'PENDING'::character varying NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    locked_at timestamp with time zone,
    locked_by character varying(150),
    published_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT outbox_retry_chk CHECK ((retry_count >= 0)),
    CONSTRAINT outbox_status_chk CHECK (((status)::text = ANY (ARRAY[('PENDING'::character varying)::text, ('PROCESSING'::character varying)::text, ('PUBLISHED'::character varying)::text, ('FAILED'::character varying)::text, ('DEAD_LETTER'::character varying)::text])))
);

ALTER TABLE ONLY public.auth_customer_outbox_events FORCE ROW LEVEL SECURITY;


--
-- Name: authentication_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authentication_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    challenge_hash character varying(128) NOT NULL,
    challenge_type character varying(30) NOT NULL,
    purpose character varying(50) NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    result character varying(30),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    subject_id uuid,
    subject_type character varying(30),
    scope_type character varying(20),
    authorization_version integer,
    CONSTRAINT authentication_challenges_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT authentication_challenges_authorization_version_check CHECK (((authorization_version IS NULL) OR (authorization_version >= 1))),
    CONSTRAINT authentication_challenges_max_attempts_check CHECK ((max_attempts > 0)),
    CONSTRAINT authentication_challenges_scope_type_check CHECK (((scope_type IS NULL) OR ((scope_type)::text = ANY (ARRAY[('TENANT'::character varying)::text, ('PLATFORM'::character varying)::text])))),
    CONSTRAINT authentication_challenges_subject_check CHECK ((((subject_id IS NULL) AND (user_id IS NULL) AND (subject_type IS NULL) AND (scope_type IS NULL)) OR ((subject_id IS NOT NULL) AND ((subject_type)::text = 'CUSTOMER'::text) AND ((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL) AND (user_id = subject_id)) OR ((subject_id IS NOT NULL) AND ((subject_type)::text = 'ADMINISTRATOR'::text) AND (user_id IS NULL) AND ((((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL)) OR (((scope_type)::text = 'PLATFORM'::text) AND (tenant_id IS NULL))) AND (authorization_version IS NOT NULL)))),
    CONSTRAINT authentication_challenges_subject_type_check CHECK (((subject_type IS NULL) OR ((subject_type)::text = ANY (ARRAY[('CUSTOMER'::character varying)::text, ('ADMINISTRATOR'::character varying)::text]))))
);

ALTER TABLE ONLY public.authentication_challenges FORCE ROW LEVEL SECURITY;


--
-- Name: credential_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credential_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_type public.credential_type NOT NULL,
    credential_hash text NOT NULL,
    credential_version integer NOT NULL,
    change_reason character varying(100),
    replaced_credential_id uuid,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    retain_until timestamp with time zone,
    CONSTRAINT credential_history_version_chk CHECK ((credential_version > 0))
);

ALTER TABLE ONLY public.credential_history FORCE ROW LEVEL SECURITY;


--
-- Name: customer_addresses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_addresses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    address_type character varying(30) NOT NULL,
    address_line_1 character varying(255) NOT NULL,
    address_line_2 character varying(255),
    city character varying(100),
    state character varying(100),
    country character varying(100) DEFAULT 'Nigeria'::character varying NOT NULL,
    postal_code character varying(20),
    latitude numeric(10,7),
    longitude numeric(10,7),
    is_primary boolean DEFAULT false NOT NULL,
    is_verified boolean DEFAULT false NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.customer_addresses FORCE ROW LEVEL SECURITY;


--
-- Name: customer_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_documents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    document_type public.kyc_document_type NOT NULL,
    document_number_encrypted text,
    document_number_hash character varying(128),
    issuing_country character varying(100),
    issued_at date,
    expires_at date,
    storage_reference text NOT NULL,
    mime_type character varying(100),
    status public.kyc_status DEFAULT 'PENDING'::public.kyc_status NOT NULL,
    verification_status public.kyc_status DEFAULT 'NOT_STARTED'::public.kyc_status NOT NULL,
    uploaded_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    rejection_reason text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    document_number_masked character varying(64),
    document_hash_key_id character varying(100),
    identity_vault_reference text,
    consent_id uuid
);

ALTER TABLE ONLY public.customer_documents FORCE ROW LEVEL SECURITY;


--
-- Name: customer_kyc_tiers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_kyc_tiers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    status public.kyc_status DEFAULT 'PENDING'::public.kyc_status NOT NULL,
    effective_from timestamp with time zone DEFAULT now() NOT NULL,
    effective_until timestamp with time zone,
    approved_at timestamp with time zone,
    approved_by uuid,
    rejection_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    kyc_tier_version_id uuid NOT NULL
);

ALTER TABLE ONLY public.customer_kyc_tiers FORCE ROW LEVEL SECURITY;


--
-- Name: customer_merge_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_merge_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    source_customer_id uuid,
    target_customer_id uuid NOT NULL,
    source_user_id uuid,
    target_user_id uuid NOT NULL,
    reason text NOT NULL,
    merge_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    merged_by uuid NOT NULL,
    merged_at timestamp with time zone DEFAULT now() NOT NULL,
    reversed_by uuid,
    reversed_at timestamp with time zone,
    reversal_reason text,
    CONSTRAINT merge_customer_chk CHECK (((source_customer_id IS NULL) OR (source_customer_id <> target_customer_id))),
    CONSTRAINT merge_user_chk CHECK (((source_user_id IS NULL) OR (source_user_id <> target_user_id)))
);

ALTER TABLE ONLY public.customer_merge_history FORCE ROW LEVEL SECURITY;


--
-- Name: customer_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_profiles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    customer_number character varying(50) NOT NULL,
    first_name character varying(100),
    middle_name character varying(100),
    last_name character varying(100),
    date_of_birth date,
    gender character varying(30),
    nationality character varying(100) DEFAULT 'Nigerian'::character varying,
    marital_status character varying(50),
    occupation character varying(150),
    employer_name character varying(255),
    employment_status character varying(50),
    profile_photo_url text,
    preferred_language character varying(20) DEFAULT 'en'::character varying,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.customer_profiles FORCE ROW LEVEL SECURITY;


--
-- Name: customer_risk_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_risk_profiles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    overall_risk_score numeric(5,2),
    risk_level public.aml_risk_level DEFAULT 'LOW'::public.aml_risk_level NOT NULL,
    fraud_score numeric(5,2),
    credit_risk_score numeric(5,2),
    behavioral_risk_score numeric(5,2),
    last_calculated_at timestamp with time zone,
    calculation_version character varying(50),
    risk_factors jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    CONSTRAINT behavioral_risk_score_chk CHECK (((behavioral_risk_score IS NULL) OR ((behavioral_risk_score >= (0)::numeric) AND (behavioral_risk_score <= (100)::numeric)))),
    CONSTRAINT credit_risk_score_chk CHECK (((credit_risk_score IS NULL) OR ((credit_risk_score >= (0)::numeric) AND (credit_risk_score <= (100)::numeric)))),
    CONSTRAINT fraud_risk_score_chk CHECK (((fraud_score IS NULL) OR ((fraud_score >= (0)::numeric) AND (fraud_score <= (100)::numeric)))),
    CONSTRAINT overall_risk_score_chk CHECK (((overall_risk_score IS NULL) OR ((overall_risk_score >= (0)::numeric) AND (overall_risk_score <= (100)::numeric))))
);

ALTER TABLE ONLY public.customer_risk_profiles FORCE ROW LEVEL SECURITY;


--
-- Name: customer_status_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_status_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    previous_status public.user_status,
    new_status public.user_status NOT NULL,
    reason text,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.customer_status_history FORCE ROW LEVEL SECURITY;


--
-- Name: data_erasure_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.data_erasure_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    customer_id uuid,
    request_type character varying(50) DEFAULT 'ERASURE'::character varying NOT NULL,
    status character varying(30) DEFAULT 'REQUESTED'::character varying NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    legal_hold_reason text,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    due_at timestamp with time zone,
    approved_by uuid,
    approved_at timestamp with time zone,
    completed_at timestamp with time zone,
    rejection_reason text,
    execution_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT erasure_status_chk CHECK (((status)::text = ANY (ARRAY[('REQUESTED'::character varying)::text, ('UNDER_REVIEW'::character varying)::text, ('APPROVED'::character varying)::text, ('REJECTED'::character varying)::text, ('PROCESSING'::character varying)::text, ('COMPLETED'::character varying)::text, ('CANCELLED'::character varying)::text]))),
    CONSTRAINT erasure_subject_chk CHECK (((user_id IS NOT NULL) OR (customer_id IS NOT NULL)))
);

ALTER TABLE ONLY public.data_erasure_requests FORCE ROW LEVEL SECURITY;


--
-- Name: fraud_flag_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fraud_flag_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    fraud_flag_id uuid NOT NULL,
    previous_status public.fraud_flag_status,
    new_status public.fraud_flag_status NOT NULL,
    previous_severity public.fraud_severity,
    new_severity public.fraud_severity,
    action character varying(100) NOT NULL,
    notes text,
    performed_by uuid,
    performed_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL
);

ALTER TABLE ONLY public.fraud_flag_events FORCE ROW LEVEL SECURITY;


--
-- Name: fraud_flags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fraud_flags (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    customer_id uuid,
    flag_type character varying(100) NOT NULL,
    status public.fraud_flag_status DEFAULT 'FLAGGED'::public.fraud_flag_status NOT NULL,
    severity public.fraud_severity DEFAULT 'MEDIUM'::public.fraud_severity NOT NULL,
    score numeric(5,2),
    reason text NOT NULL,
    source character varying(100),
    source_reference character varying(255),
    assigned_to uuid,
    flagged_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_at timestamp with time zone,
    cleared_at timestamp with time zone,
    blocked_at timestamp with time zone,
    resolution_notes text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    CONSTRAINT fraud_score_chk CHECK (((score IS NULL) OR ((score >= (0)::numeric) AND (score <= (100)::numeric))))
);

ALTER TABLE ONLY public.fraud_flags FORCE ROW LEVEL SECURITY;


--
-- Name: idempotency_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.idempotency_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    idempotency_key character varying(255) NOT NULL,
    operation character varying(150) NOT NULL,
    request_hash character varying(128) NOT NULL,
    resource_type character varying(100),
    resource_id uuid,
    response_code integer,
    response_body jsonb,
    status character varying(30) DEFAULT 'PROCESSING'::character varying NOT NULL,
    locked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT idempotency_status_chk CHECK (((status)::text = ANY (ARRAY[('PROCESSING'::character varying)::text, ('COMPLETED'::character varying)::text, ('FAILED'::character varying)::text])))
);

ALTER TABLE ONLY public.idempotency_keys FORCE ROW LEVEL SECURITY;


--
-- Name: identity_verification_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_verification_evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    verification_id uuid NOT NULL,
    consent_id uuid NOT NULL,
    identifier_type public.verification_type NOT NULL,
    identifier_masked character varying(64) NOT NULL,
    identifier_hash character varying(128) NOT NULL,
    hash_key_id character varying(100) NOT NULL,
    provider_reference character varying(255) NOT NULL,
    provider_configuration_version character varying(100) NOT NULL,
    result_digest character varying(128) NOT NULL,
    result_signature text NOT NULL,
    signing_key_id character varying(100) NOT NULL,
    identity_vault_reference text,
    verified_at timestamp with time zone NOT NULL,
    retain_until timestamp with time zone NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.identity_verification_evidence FORCE ROW LEVEL SECURITY;


--
-- Name: kyc_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kyc_profiles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    status public.kyc_status DEFAULT 'NOT_STARTED'::public.kyc_status NOT NULL,
    overall_score numeric(5,2),
    risk_level public.aml_risk_level,
    last_verified_at timestamp with time zone,
    next_review_at timestamp with time zone,
    rejection_reason text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    CONSTRAINT kyc_score_chk CHECK (((overall_score IS NULL) OR ((overall_score >= (0)::numeric) AND (overall_score <= (100)::numeric))))
);

ALTER TABLE ONLY public.kyc_profiles FORCE ROW LEVEL SECURITY;


--
-- Name: kyc_tier_standards; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kyc_tier_standards (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code character varying(30) NOT NULL,
    name character varying(100) NOT NULL,
    level smallint NOT NULL,
    description text,
    requirements jsonb DEFAULT '{}'::jsonb NOT NULL,
    transaction_limits jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT kyc_tier_level_chk CHECK (((level >= 1) AND (level <= 3)))
);


--
-- Name: kyc_tier_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kyc_tier_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    standard_tier_id uuid,
    code character varying(30) NOT NULL,
    name character varying(100) NOT NULL,
    version integer NOT NULL,
    status character varying(20) DEFAULT 'DRAFT'::character varying NOT NULL,
    requirements jsonb DEFAULT '{}'::jsonb NOT NULL,
    daily_transaction_limit_minor bigint NOT NULL,
    balance_ceiling_minor bigint,
    currency character(3) DEFAULT 'NGN'::bpchar NOT NULL,
    effective_from timestamp with time zone,
    published_at timestamp with time zone,
    published_by uuid,
    approval_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT kyc_tier_versions_balance_ceiling_minor_check CHECK (((balance_ceiling_minor IS NULL) OR (balance_ceiling_minor >= 0))),
    CONSTRAINT kyc_tier_versions_check CHECK ((((status)::text = 'DRAFT'::text) OR ((published_at IS NOT NULL) AND (approval_id IS NOT NULL)))),
    CONSTRAINT kyc_tier_versions_currency_check CHECK ((currency ~ '^[A-Z]{3}$'::text)),
    CONSTRAINT kyc_tier_versions_daily_transaction_limit_minor_check CHECK ((daily_transaction_limit_minor >= 0)),
    CONSTRAINT kyc_tier_versions_status_check CHECK (((status)::text = ANY (ARRAY[('DRAFT'::character varying)::text, ('PUBLISHED'::character varying)::text, ('RETIRED'::character varying)::text]))),
    CONSTRAINT kyc_tier_versions_version_check CHECK ((version > 0))
);

ALTER TABLE ONLY public.kyc_tier_versions FORCE ROW LEVEL SECURITY;


--
-- Name: kyc_verification_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kyc_verification_results (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    verification_id uuid NOT NULL,
    result_code character varying(100),
    result_status public.kyc_status NOT NULL,
    confidence_score numeric(5,2),
    response_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT kyc_confidence_chk CHECK (((confidence_score IS NULL) OR ((confidence_score >= (0)::numeric) AND (confidence_score <= (100)::numeric))))
);

ALTER TABLE ONLY public.kyc_verification_results FORCE ROW LEVEL SECURITY;


--
-- Name: kyc_verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kyc_verifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    document_id uuid,
    verification_type public.verification_type NOT NULL,
    provider_name character varying(100) NOT NULL,
    provider_reference character varying(255),
    status public.kyc_status DEFAULT 'PENDING'::public.kyc_status NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    failure_reason text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    consent_id uuid,
    provider_configuration_version character varying(100)
);

ALTER TABLE ONLY public.kyc_verifications FORCE ROW LEVEL SECURITY;


--
-- Name: login_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    identifier character varying(255),
    success boolean NOT NULL,
    failure_reason character varying(100),
    ip_address inet,
    user_agent text,
    device_id uuid,
    attempted_at timestamp with time zone DEFAULT now() NOT NULL,
    retain_until timestamp with time zone DEFAULT (now() + '2 years'::interval) NOT NULL
);

ALTER TABLE ONLY public.login_attempts FORCE ROW LEVEL SECURITY;


--
-- Name: notification_delivery_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_delivery_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    notification_id uuid NOT NULL,
    channel public.notification_channel NOT NULL,
    provider_name character varying(100) NOT NULL,
    provider_configuration_version character varying(100) NOT NULL,
    target_hash character varying(128) NOT NULL,
    hash_key_id character varying(100) NOT NULL,
    attempt_number integer NOT NULL,
    status character varying(30) NOT NULL,
    provider_reference character varying(255),
    failure_code character varying(100),
    response_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    next_retry_at timestamp with time zone,
    metadata_retain_until timestamp with time zone NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT notification_delivery_attempts_attempt_number_check CHECK ((attempt_number > 0)),
    CONSTRAINT notification_delivery_attempts_check CHECK (((((status)::text = 'PROCESSING'::text) AND (completed_at IS NULL)) OR (((status)::text <> 'PROCESSING'::text) AND (completed_at IS NOT NULL)))),
    CONSTRAINT notification_delivery_attempts_check1 CHECK (((((status)::text = 'RETRYABLE'::text) AND (next_retry_at IS NOT NULL)) OR ((status)::text <> 'RETRYABLE'::text))),
    CONSTRAINT notification_delivery_attempts_status_check CHECK (((status)::text = ANY ((ARRAY['PROCESSING'::character varying, 'SENT'::character varying, 'DELIVERED'::character varying, 'RETRYABLE'::character varying, 'FAILED'::character varying])::text[])))
);

ALTER TABLE ONLY public.notification_delivery_attempts FORCE ROW LEVEL SECURITY;


--
-- Name: notification_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_preferences (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    notification_category character varying(100) NOT NULL,
    push_enabled boolean DEFAULT true NOT NULL,
    sms_enabled boolean DEFAULT true NOT NULL,
    email_enabled boolean DEFAULT true NOT NULL,
    in_app_enabled boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.notification_preferences FORCE ROW LEVEL SECURITY;


--
-- Name: notification_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_templates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    template_code character varying(100) NOT NULL,
    channel public.notification_channel NOT NULL,
    subject_template text,
    body_template text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.notification_templates FORCE ROW LEVEL SECURITY;


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    template_id uuid,
    channel public.notification_channel NOT NULL,
    recipient character varying(255),
    subject text,
    body text NOT NULL,
    status public.notification_status DEFAULT 'PENDING'::public.notification_status NOT NULL,
    scheduled_at timestamp with time zone,
    sent_at timestamp with time zone,
    delivered_at timestamp with time zone,
    read_at timestamp with time zone,
    failed_at timestamp with time zone,
    failure_reason text,
    provider_name character varying(100),
    provider_reference character varying(255),
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    classification character varying(30) DEFAULT 'NON_FINANCIAL'::character varying NOT NULL,
    content_retain_until timestamp with time zone,
    metadata_retain_until timestamp with time zone,
    legal_hold boolean DEFAULT false NOT NULL,
    CONSTRAINT notifications_classification_check CHECK (((classification)::text = ANY (ARRAY[('NON_FINANCIAL'::character varying)::text, ('FINANCIAL'::character varying)::text, ('CONTRACTUAL'::character varying)::text, ('KYC'::character varying)::text, ('SECURITY'::character varying)::text, ('COMPLAINT'::character varying)::text])))
);

ALTER TABLE ONLY public.notifications FORCE ROW LEVEL SECURITY;


--
-- Name: otp_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.otp_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    purpose public.otp_purpose NOT NULL,
    channel public.notification_channel NOT NULL,
    destination character varying(255) NOT NULL,
    otp_hash text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT otp_attempts_chk CHECK ((attempts >= 0)),
    CONSTRAINT otp_max_attempts_chk CHECK ((max_attempts > 0))
);

ALTER TABLE ONLY public.otp_challenges FORCE ROW LEVEL SECURITY;


--
-- Name: password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.password_reset_tokens FORCE ROW LEVEL SECURITY;


--
-- Name: provider_webhook_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_webhook_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    provider_name character varying(100) NOT NULL,
    provider_event_id character varying(255) NOT NULL,
    event_type character varying(150) NOT NULL,
    signature_valid boolean DEFAULT false NOT NULL,
    payload jsonb NOT NULL,
    headers jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(30) DEFAULT 'RECEIVED'::character varying NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    next_retry_at timestamp with time zone,
    last_error text,
    retain_until timestamp with time zone DEFAULT (now() + '30 days'::interval) NOT NULL,
    CONSTRAINT webhook_retry_chk CHECK ((retry_count >= 0)),
    CONSTRAINT webhook_status_chk CHECK (((status)::text = ANY (ARRAY[('RECEIVED'::character varying)::text, ('VERIFIED'::character varying)::text, ('PROCESSING'::character varying)::text, ('PROCESSED'::character varying)::text, ('REJECTED'::character varying)::text, ('FAILED'::character varying)::text, ('DEAD_LETTER'::character varying)::text])))
);

ALTER TABLE ONLY public.provider_webhook_events FORCE ROW LEVEL SECURITY;


--
-- Name: referral_programs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.referral_programs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    program_code character varying(50) NOT NULL,
    name character varying(150) NOT NULL,
    description text,
    start_at timestamp with time zone NOT NULL,
    end_at timestamp with time zone,
    currency_code character(3) DEFAULT 'NGN'::bpchar NOT NULL,
    qualification_rules jsonb DEFAULT '{}'::jsonb NOT NULL,
    reward_rules jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    referrer_reward_amount_minor bigint,
    referee_reward_amount_minor bigint,
    CONSTRAINT referral_programs_referee_reward_amount_minor_check CHECK (((referee_reward_amount_minor IS NULL) OR (referee_reward_amount_minor >= 0))),
    CONSTRAINT referral_programs_referrer_reward_amount_minor_check CHECK (((referrer_reward_amount_minor IS NULL) OR (referrer_reward_amount_minor >= 0)))
);

ALTER TABLE ONLY public.referral_programs FORCE ROW LEVEL SECURITY;


--
-- Name: referral_reward_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.referral_reward_transactions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    reward_id uuid NOT NULL,
    transaction_id uuid,
    transaction_type character varying(50) NOT NULL,
    currency_code character(3) DEFAULT 'NGN'::bpchar NOT NULL,
    status public.reward_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    amount_minor bigint NOT NULL,
    CONSTRAINT referral_reward_transactions_amount_minor_check CHECK ((amount_minor > 0))
);

ALTER TABLE ONLY public.referral_reward_transactions FORCE ROW LEVEL SECURITY;


--
-- Name: referral_rewards; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.referral_rewards (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    referral_id uuid NOT NULL,
    beneficiary_user_id uuid NOT NULL,
    reward_type character varying(50) NOT NULL,
    currency_code character(3) DEFAULT 'NGN'::bpchar NOT NULL,
    status public.reward_status DEFAULT 'PENDING'::public.reward_status NOT NULL,
    qualification_reference character varying(255),
    approved_at timestamp with time zone,
    paid_at timestamp with time zone,
    reversed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    amount_minor bigint NOT NULL,
    CONSTRAINT referral_rewards_amount_minor_check CHECK ((amount_minor > 0))
);

ALTER TABLE ONLY public.referral_rewards FORCE ROW LEVEL SECURITY;


--
-- Name: referrals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.referrals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    program_id uuid NOT NULL,
    referrer_user_id uuid NOT NULL,
    referred_user_id uuid,
    referral_code character varying(30) NOT NULL,
    status public.referral_status DEFAULT 'PENDING'::public.referral_status NOT NULL,
    qualified_at timestamp with time zone,
    rewarded_at timestamp with time zone,
    expires_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT referral_self_check CHECK (((referred_user_id IS NULL) OR (referrer_user_id <> referred_user_id)))
);

ALTER TABLE ONLY public.referrals FORCE ROW LEVEL SECURITY;


--
-- Name: risk_assessment_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.risk_assessment_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    assessment_type character varying(50) NOT NULL,
    overall_risk_score numeric(5,2),
    risk_level public.aml_risk_level NOT NULL,
    fraud_score numeric(5,2),
    credit_risk_score numeric(5,2),
    behavioral_risk_score numeric(5,2),
    risk_factors jsonb DEFAULT '{}'::jsonb NOT NULL,
    calculation_version character varying(50) NOT NULL,
    model_reference character varying(150),
    triggered_by character varying(100),
    correlation_id uuid,
    assessed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT risk_history_behavioral_chk CHECK (((behavioral_risk_score IS NULL) OR ((behavioral_risk_score >= (0)::numeric) AND (behavioral_risk_score <= (100)::numeric)))),
    CONSTRAINT risk_history_credit_chk CHECK (((credit_risk_score IS NULL) OR ((credit_risk_score >= (0)::numeric) AND (credit_risk_score <= (100)::numeric)))),
    CONSTRAINT risk_history_fraud_chk CHECK (((fraud_score IS NULL) OR ((fraud_score >= (0)::numeric) AND (fraud_score <= (100)::numeric)))),
    CONSTRAINT risk_history_overall_chk CHECK (((overall_risk_score IS NULL) OR ((overall_risk_score >= (0)::numeric) AND (overall_risk_score <= (100)::numeric))))
);

ALTER TABLE ONLY public.risk_assessment_history FORCE ROW LEVEL SECURITY;


--
-- Name: user_2fa_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_2fa_methods (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    method_type public.two_fa_method_type NOT NULL,
    identifier character varying(255),
    secret_encrypted text,
    is_primary boolean DEFAULT false NOT NULL,
    is_verified boolean DEFAULT false NOT NULL,
    verified_at timestamp with time zone,
    enabled_at timestamp with time zone,
    disabled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    encryption_key_id character varying(100),
    subject_id uuid NOT NULL,
    subject_type character varying(30) DEFAULT 'CUSTOMER'::character varying NOT NULL,
    scope_type character varying(20) DEFAULT 'TENANT'::character varying NOT NULL,
    CONSTRAINT user_2fa_scope_type_check CHECK (((scope_type)::text = ANY (ARRAY[('TENANT'::character varying)::text, ('PLATFORM'::character varying)::text]))),
    CONSTRAINT user_2fa_subject_ownership_check CHECK (((((subject_type)::text = 'CUSTOMER'::text) AND ((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL) AND (user_id = subject_id)) OR (((subject_type)::text = 'ADMINISTRATOR'::text) AND (user_id IS NULL) AND ((((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL)) OR (((scope_type)::text = 'PLATFORM'::text) AND (tenant_id IS NULL)))))),
    CONSTRAINT user_2fa_subject_type_check CHECK (((subject_type)::text = ANY (ARRAY[('CUSTOMER'::character varying)::text, ('ADMINISTRATOR'::character varying)::text])))
);

ALTER TABLE ONLY public.user_2fa_methods FORCE ROW LEVEL SECURITY;


--
-- Name: user_biometric_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_biometric_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_id uuid,
    biometric_type public.biometric_type NOT NULL,
    credential_reference text NOT NULL,
    public_key text,
    is_active boolean DEFAULT true NOT NULL,
    registered_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.user_biometric_credentials FORCE ROW LEVEL SECURITY;


--
-- Name: user_consents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_consents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    consent_type public.consent_type NOT NULL,
    document_version character varying(50) NOT NULL,
    granted boolean NOT NULL,
    granted_at timestamp with time zone,
    withdrawn_at timestamp with time zone,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    purpose character varying(150),
    channel character varying(30),
    policy_uri text,
    evidence_digest character varying(128),
    consent_document_id uuid NOT NULL
);

ALTER TABLE ONLY public.user_consents FORCE ROW LEVEL SECURITY;


--
-- Name: COLUMN user_consents.consent_document_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.user_consents.consent_document_id IS 'External immutable consent-document identifier owned by Tenant Admin; intentionally no cross-database foreign key';


--
-- Name: user_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_type public.credential_type NOT NULL,
    credential_hash text NOT NULL,
    credential_version integer DEFAULT 1 NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    last_used_at timestamp with time zone,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.user_credentials FORCE ROW LEVEL SECURITY;


--
-- Name: user_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_devices (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_identifier character varying(255) NOT NULL,
    device_name character varying(150),
    platform character varying(30),
    os_version character varying(50),
    app_version character varying(50),
    push_token text,
    status public.device_status DEFAULT 'ACTIVE'::public.device_status NOT NULL,
    is_trusted boolean DEFAULT false NOT NULL,
    last_seen_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.user_devices FORCE ROW LEVEL SECURITY;


--
-- Name: user_passkeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_passkeys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    credential_id text NOT NULL,
    public_key text NOT NULL,
    relying_party_id character varying(255) NOT NULL,
    aaguid uuid,
    sign_count bigint DEFAULT 0 NOT NULL,
    transports text[] DEFAULT ARRAY[]::text[] NOT NULL,
    backup_eligible boolean DEFAULT false NOT NULL,
    backup_state boolean DEFAULT false NOT NULL,
    device_type character varying(50),
    friendly_name character varying(150),
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    subject_id uuid NOT NULL,
    subject_type character varying(30) DEFAULT 'CUSTOMER'::character varying NOT NULL,
    scope_type character varying(20) DEFAULT 'TENANT'::character varying NOT NULL,
    CONSTRAINT passkey_sign_count_chk CHECK ((sign_count >= 0)),
    CONSTRAINT user_passkeys_scope_type_check CHECK (((scope_type)::text = ANY ((ARRAY['TENANT'::character varying, 'PLATFORM'::character varying])::text[]))),
    CONSTRAINT user_passkeys_subject_ownership_check CHECK (((((subject_type)::text = 'CUSTOMER'::text) AND ((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL) AND (user_id = subject_id)) OR (((subject_type)::text = 'ADMINISTRATOR'::text) AND (user_id IS NULL) AND ((((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL)) OR (((scope_type)::text = 'PLATFORM'::text) AND (tenant_id IS NULL)))))),
    CONSTRAINT user_passkeys_subject_type_check CHECK (((subject_type)::text = ANY ((ARRAY['CUSTOMER'::character varying, 'ADMINISTRATOR'::character varying])::text[])))
);

ALTER TABLE ONLY public.user_passkeys FORCE ROW LEVEL SECURITY;


--
-- Name: user_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    device_id uuid,
    session_token_hash text NOT NULL,
    refresh_token_hash text,
    ip_address inet,
    user_agent text,
    expires_at timestamp with time zone NOT NULL,
    last_activity_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    token_family_id uuid DEFAULT gen_random_uuid() NOT NULL,
    rotation_sequence integer DEFAULT 0 NOT NULL,
    replaced_by_session_id uuid,
    reuse_detected_at timestamp with time zone,
    compromised_at timestamp with time zone,
    audience character varying(100) DEFAULT 'parc-mobile'::character varying NOT NULL,
    subject_type character varying(30) DEFAULT 'CUSTOMER'::character varying NOT NULL,
    authentication_methods text[] DEFAULT '{}'::text[] NOT NULL,
    mfa_verified_at timestamp with time zone,
    idle_expires_at timestamp with time zone,
    subject_id uuid NOT NULL,
    scope_type character varying(20) DEFAULT 'TENANT'::character varying NOT NULL,
    authorization_version integer,
    CONSTRAINT user_sessions_authorization_version_check CHECK (((authorization_version IS NULL) OR (authorization_version >= 1))),
    CONSTRAINT user_sessions_rotation_sequence_check CHECK ((rotation_sequence >= 0)),
    CONSTRAINT user_sessions_scope_type_check CHECK (((scope_type)::text = ANY (ARRAY[('TENANT'::character varying)::text, ('PLATFORM'::character varying)::text]))),
    CONSTRAINT user_sessions_subject_ownership_check CHECK (((((subject_type)::text = 'CUSTOMER'::text) AND ((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL) AND (user_id = subject_id) AND (authorization_version IS NULL)) OR (((subject_type)::text = 'ADMINISTRATOR'::text) AND (user_id IS NULL) AND ((((scope_type)::text = 'TENANT'::text) AND (tenant_id IS NOT NULL)) OR (((scope_type)::text = 'PLATFORM'::text) AND (tenant_id IS NULL))) AND (authorization_version IS NOT NULL)))),
    CONSTRAINT user_sessions_subject_type_check CHECK (((subject_type)::text = ANY (ARRAY[('CUSTOMER'::character varying)::text, ('ADMINISTRATOR'::character varying)::text])))
);

ALTER TABLE ONLY public.user_sessions FORCE ROW LEVEL SECURITY;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_type public.user_type DEFAULT 'CUSTOMER'::public.user_type NOT NULL,
    status public.user_status DEFAULT 'PENDING'::public.user_status NOT NULL,
    phone character varying(30),
    email character varying(255),
    phone_verified boolean DEFAULT false NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    phone_verified_at timestamp with time zone,
    email_verified_at timestamp with time zone,
    referral_code character varying(30),
    last_login_at timestamp with time zone,
    last_login_ip inet,
    failed_login_attempts integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    phone_normalized character varying(30),
    email_normalized character varying(255),
    CONSTRAINT users_customer_boundary_chk CHECK ((user_type <> 'STAFF'::public.user_type)),
    CONSTRAINT users_email_chk CHECK (((email IS NULL) OR ((email)::text ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$'::text))),
    CONSTRAINT users_failed_login_chk CHECK ((failed_login_attempts >= 0))
);

ALTER TABLE ONLY public.users FORCE ROW LEVEL SECURITY;


--
-- Name: account_recovery_requests account_recovery_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_recovery_requests
    ADD CONSTRAINT account_recovery_requests_pkey PRIMARY KEY (id);


--
-- Name: aml_profiles aml_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aml_profiles
    ADD CONSTRAINT aml_profiles_pkey PRIMARY KEY (id);


--
-- Name: aml_screening_checks aml_screening_checks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aml_screening_checks
    ADD CONSTRAINT aml_screening_checks_pkey PRIMARY KEY (id);


--
-- Name: aml_screening_results aml_screening_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aml_screening_results
    ADD CONSTRAINT aml_screening_results_pkey PRIMARY KEY (id);


--
-- Name: auth_audit_events auth_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_audit_events
    ADD CONSTRAINT auth_audit_events_pkey PRIMARY KEY (id);


--
-- Name: auth_customer_inbox_events auth_customer_inbox_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_customer_inbox_events
    ADD CONSTRAINT auth_customer_inbox_events_pkey PRIMARY KEY (id);


--
-- Name: auth_customer_outbox_events auth_customer_outbox_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_customer_outbox_events
    ADD CONSTRAINT auth_customer_outbox_events_pkey PRIMARY KEY (id);


--
-- Name: authentication_challenges authentication_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authentication_challenges
    ADD CONSTRAINT authentication_challenges_pkey PRIMARY KEY (id);


--
-- Name: authentication_challenges authentication_challenges_tenant_id_challenge_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authentication_challenges
    ADD CONSTRAINT authentication_challenges_tenant_id_challenge_hash_key UNIQUE (tenant_id, challenge_hash);


--
-- Name: credential_history credential_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential_history
    ADD CONSTRAINT credential_history_pkey PRIMARY KEY (id);


--
-- Name: customer_addresses customer_addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_addresses
    ADD CONSTRAINT customer_addresses_pkey PRIMARY KEY (id);


--
-- Name: customer_documents customer_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_documents
    ADD CONSTRAINT customer_documents_pkey PRIMARY KEY (id);


--
-- Name: customer_kyc_tiers customer_kyc_tiers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_kyc_tiers
    ADD CONSTRAINT customer_kyc_tiers_pkey PRIMARY KEY (id);


--
-- Name: customer_merge_history customer_merge_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_merge_history
    ADD CONSTRAINT customer_merge_history_pkey PRIMARY KEY (id);


--
-- Name: customer_profiles customer_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_profiles
    ADD CONSTRAINT customer_profiles_pkey PRIMARY KEY (id);


--
-- Name: customer_risk_profiles customer_risk_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_risk_profiles
    ADD CONSTRAINT customer_risk_profiles_pkey PRIMARY KEY (id);


--
-- Name: customer_status_history customer_status_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_status_history
    ADD CONSTRAINT customer_status_history_pkey PRIMARY KEY (id);


--
-- Name: data_erasure_requests data_erasure_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_erasure_requests
    ADD CONSTRAINT data_erasure_requests_pkey PRIMARY KEY (id);


--
-- Name: fraud_flag_events fraud_flag_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fraud_flag_events
    ADD CONSTRAINT fraud_flag_events_pkey PRIMARY KEY (id);


--
-- Name: fraud_flags fraud_flags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fraud_flags
    ADD CONSTRAINT fraud_flags_pkey PRIMARY KEY (id);


--
-- Name: idempotency_keys idempotency_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (id);


--
-- Name: identity_verification_evidence identity_verification_evidenc_tenant_id_identifier_type_ide_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_verification_evidence
    ADD CONSTRAINT identity_verification_evidenc_tenant_id_identifier_type_ide_key UNIQUE (tenant_id, identifier_type, identifier_hash, provider_reference);


--
-- Name: identity_verification_evidence identity_verification_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_verification_evidence
    ADD CONSTRAINT identity_verification_evidence_pkey PRIMARY KEY (id);


--
-- Name: kyc_profiles kyc_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_profiles
    ADD CONSTRAINT kyc_profiles_pkey PRIMARY KEY (id);


--
-- Name: kyc_tier_versions kyc_tier_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_tier_versions
    ADD CONSTRAINT kyc_tier_versions_pkey PRIMARY KEY (id);


--
-- Name: kyc_tier_versions kyc_tier_versions_tenant_id_code_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_tier_versions
    ADD CONSTRAINT kyc_tier_versions_tenant_id_code_version_key UNIQUE (tenant_id, code, version);


--
-- Name: kyc_tier_standards kyc_tiers_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_tier_standards
    ADD CONSTRAINT kyc_tiers_code_key UNIQUE (code);


--
-- Name: kyc_tier_standards kyc_tiers_level_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_tier_standards
    ADD CONSTRAINT kyc_tiers_level_key UNIQUE (level);


--
-- Name: kyc_tier_standards kyc_tiers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_tier_standards
    ADD CONSTRAINT kyc_tiers_pkey PRIMARY KEY (id);


--
-- Name: kyc_verification_results kyc_verification_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_verification_results
    ADD CONSTRAINT kyc_verification_results_pkey PRIMARY KEY (id);


--
-- Name: kyc_verifications kyc_verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_verifications
    ADD CONSTRAINT kyc_verifications_pkey PRIMARY KEY (id);


--
-- Name: login_attempts login_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_attempts
    ADD CONSTRAINT login_attempts_pkey PRIMARY KEY (id);


--
-- Name: notification_delivery_attempts notification_delivery_attempt_tenant_id_notification_id_tar_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_delivery_attempts
    ADD CONSTRAINT notification_delivery_attempt_tenant_id_notification_id_tar_key UNIQUE (tenant_id, notification_id, target_hash, attempt_number);


--
-- Name: notification_delivery_attempts notification_delivery_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_delivery_attempts
    ADD CONSTRAINT notification_delivery_attempts_pkey PRIMARY KEY (id);


--
-- Name: notification_preferences notification_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_pkey PRIMARY KEY (id);


--
-- Name: notification_templates notification_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_templates
    ADD CONSTRAINT notification_templates_pkey PRIMARY KEY (id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: otp_challenges otp_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.otp_challenges
    ADD CONSTRAINT otp_challenges_pkey PRIMARY KEY (id);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: provider_webhook_events provider_webhook_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_webhook_events
    ADD CONSTRAINT provider_webhook_events_pkey PRIMARY KEY (id);


--
-- Name: referral_programs referral_programs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referral_programs
    ADD CONSTRAINT referral_programs_pkey PRIMARY KEY (id);


--
-- Name: referral_reward_transactions referral_reward_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referral_reward_transactions
    ADD CONSTRAINT referral_reward_transactions_pkey PRIMARY KEY (id);


--
-- Name: referral_rewards referral_rewards_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referral_rewards
    ADD CONSTRAINT referral_rewards_pkey PRIMARY KEY (id);


--
-- Name: referrals referrals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_pkey PRIMARY KEY (id);


--
-- Name: risk_assessment_history risk_assessment_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_assessment_history
    ADD CONSTRAINT risk_assessment_history_pkey PRIMARY KEY (id);


--
-- Name: auth_customer_inbox_events uq_auth_customer_inbox_event; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_customer_inbox_events
    ADD CONSTRAINT uq_auth_customer_inbox_event UNIQUE (source_service, event_id);


--
-- Name: auth_customer_outbox_events uq_auth_customer_outbox_event; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_customer_outbox_events
    ADD CONSTRAINT uq_auth_customer_outbox_event UNIQUE (event_id);


--
-- Name: aml_profiles uq_customer_aml_profile; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aml_profiles
    ADD CONSTRAINT uq_customer_aml_profile UNIQUE (customer_id);


--
-- Name: kyc_profiles uq_customer_kyc_profile; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_profiles
    ADD CONSTRAINT uq_customer_kyc_profile UNIQUE (customer_id);


--
-- Name: customer_profiles uq_customer_number; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_profiles
    ADD CONSTRAINT uq_customer_number UNIQUE (tenant_id, customer_number);


--
-- Name: customer_risk_profiles uq_customer_risk_profile; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_risk_profiles
    ADD CONSTRAINT uq_customer_risk_profile UNIQUE (customer_id);


--
-- Name: customer_profiles uq_customer_user; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_profiles
    ADD CONSTRAINT uq_customer_user UNIQUE (user_id);


--
-- Name: idempotency_keys uq_idempotency_scope; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT uq_idempotency_scope UNIQUE (tenant_id, operation, idempotency_key);


--
-- Name: notification_preferences uq_notification_preference; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT uq_notification_preference UNIQUE (user_id, notification_category);


--
-- Name: provider_webhook_events uq_provider_webhook; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_webhook_events
    ADD CONSTRAINT uq_provider_webhook UNIQUE (tenant_id, provider_name, provider_event_id);


--
-- Name: referral_programs uq_referral_program; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referral_programs
    ADD CONSTRAINT uq_referral_program UNIQUE (tenant_id, program_code);


--
-- Name: user_2fa_methods user_2fa_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_2fa_methods
    ADD CONSTRAINT user_2fa_methods_pkey PRIMARY KEY (id);


--
-- Name: user_biometric_credentials user_biometric_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_biometric_credentials
    ADD CONSTRAINT user_biometric_credentials_pkey PRIMARY KEY (id);


--
-- Name: user_consents user_consents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_consents
    ADD CONSTRAINT user_consents_pkey PRIMARY KEY (id);


--
-- Name: user_credentials user_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_credentials
    ADD CONSTRAINT user_credentials_pkey PRIMARY KEY (id);


--
-- Name: user_devices user_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT user_devices_pkey PRIMARY KEY (id);


--
-- Name: user_passkeys user_passkeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_passkeys
    ADD CONSTRAINT user_passkeys_pkey PRIMARY KEY (id);


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_2fa_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_2fa_subject ON public.user_2fa_methods USING btree (subject_type, scope_type, tenant_id, subject_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_aml_checks_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aml_checks_customer ON public.aml_screening_checks USING btree (customer_id, initiated_at DESC);


--
-- Name: idx_aml_checks_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aml_checks_status ON public.aml_screening_checks USING btree (tenant_id, status);


--
-- Name: idx_aml_profiles_risk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aml_profiles_risk ON public.aml_profiles USING btree (tenant_id, risk_level);


--
-- Name: idx_aml_profiles_screening; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aml_profiles_screening ON public.aml_profiles USING btree (next_screening_at);


--
-- Name: idx_aml_results_check; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aml_results_check ON public.aml_screening_results USING btree (screening_check_id);


--
-- Name: idx_aml_results_match; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aml_results_match ON public.aml_screening_results USING btree (tenant_id, match_found);


--
-- Name: idx_auth_audit_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_audit_resource ON public.auth_audit_events USING btree (resource_type, resource_id, occurred_at DESC);


--
-- Name: idx_auth_audit_tenant_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_audit_tenant_time ON public.auth_audit_events USING btree (tenant_id, occurred_at DESC);


--
-- Name: idx_auth_audit_user_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_audit_user_time ON public.auth_audit_events USING btree (user_id, occurred_at DESC);


--
-- Name: idx_auth_challenge_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_challenge_expiry ON public.authentication_challenges USING btree (expires_at) WHERE (consumed_at IS NULL);


--
-- Name: idx_auth_challenge_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_challenge_subject ON public.authentication_challenges USING btree (subject_type, scope_type, tenant_id, subject_id) WHERE (consumed_at IS NULL);


--
-- Name: idx_auth_customer_inbox_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_customer_inbox_tenant ON public.auth_customer_inbox_events USING btree (tenant_id, received_at DESC);


--
-- Name: idx_auth_customer_inbox_work; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_customer_inbox_work ON public.auth_customer_inbox_events USING btree (status, next_retry_at, received_at) WHERE ((status)::text = ANY (ARRAY[('RECEIVED'::character varying)::text, ('FAILED'::character varying)::text]));


--
-- Name: idx_auth_customer_outbox_aggregate; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_customer_outbox_aggregate ON public.auth_customer_outbox_events USING btree (tenant_id, aggregate_type, aggregate_id, created_at);


--
-- Name: idx_auth_customer_outbox_work; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_customer_outbox_work ON public.auth_customer_outbox_events USING btree (status, available_at, created_at) WHERE ((status)::text = ANY (ARRAY[('PENDING'::character varying)::text, ('FAILED'::character varying)::text]));


--
-- Name: idx_biometric_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_biometric_user ON public.user_biometric_credentials USING btree (user_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_credential_history_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credential_history_user ON public.credential_history USING btree (user_id, credential_type, created_at DESC);


--
-- Name: idx_customer_addresses_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_addresses_customer ON public.customer_addresses USING btree (customer_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_customer_addresses_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_addresses_type ON public.customer_addresses USING btree (customer_id, address_type);


--
-- Name: idx_customer_documents_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_documents_customer ON public.customer_documents USING btree (customer_id);


--
-- Name: idx_customer_documents_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_documents_type ON public.customer_documents USING btree (tenant_id, document_type);


--
-- Name: idx_customer_kyc_tier_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_kyc_tier_active ON public.customer_kyc_tiers USING btree (tenant_id, customer_id, status);


--
-- Name: idx_customer_kyc_tier_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_kyc_tier_customer ON public.customer_kyc_tiers USING btree (customer_id);


--
-- Name: idx_customer_kyc_tier_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_kyc_tier_version ON public.customer_kyc_tiers USING btree (kyc_tier_version_id);


--
-- Name: idx_customer_merge_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_merge_target ON public.customer_merge_history USING btree (tenant_id, target_customer_id, merged_at DESC);


--
-- Name: idx_customer_profiles_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_profiles_name ON public.customer_profiles USING btree (tenant_id, last_name, first_name) WHERE (deleted_at IS NULL);


--
-- Name: idx_customer_profiles_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_profiles_tenant ON public.customer_profiles USING btree (tenant_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_customer_risk_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_risk_level ON public.customer_risk_profiles USING btree (tenant_id, risk_level);


--
-- Name: idx_customer_risk_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_risk_score ON public.customer_risk_profiles USING btree (tenant_id, overall_risk_score DESC);


--
-- Name: idx_customer_status_history_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customer_status_history_user ON public.customer_status_history USING btree (user_id, changed_at DESC);


--
-- Name: idx_erasure_work; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_erasure_work ON public.data_erasure_requests USING btree (tenant_id, status, due_at);


--
-- Name: idx_fraud_flag_events_flag; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fraud_flag_events_flag ON public.fraud_flag_events USING btree (fraud_flag_id, performed_at DESC);


--
-- Name: idx_fraud_flag_events_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fraud_flag_events_tenant ON public.fraud_flag_events USING btree (tenant_id, performed_at DESC);


--
-- Name: idx_fraud_flags_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fraud_flags_active ON public.fraud_flags USING btree (tenant_id, user_id) WHERE ((status = ANY (ARRAY['FLAGGED'::public.fraud_flag_status, 'UNDER_REVIEW'::public.fraud_flag_status, 'BLOCKED'::public.fraud_flag_status])) AND (deleted_at IS NULL));


--
-- Name: idx_fraud_flags_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fraud_flags_status ON public.fraud_flags USING btree (tenant_id, status, severity);


--
-- Name: idx_fraud_flags_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fraud_flags_user ON public.fraud_flags USING btree (user_id, created_at DESC);


--
-- Name: idx_idempotency_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_idempotency_expiry ON public.idempotency_keys USING btree (expires_at);


--
-- Name: idx_kyc_profiles_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_profiles_status ON public.kyc_profiles USING btree (tenant_id, status);


--
-- Name: idx_kyc_profiles_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_profiles_tenant ON public.kyc_profiles USING btree (tenant_id);


--
-- Name: idx_kyc_results_verification; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_results_verification ON public.kyc_verification_results USING btree (verification_id);


--
-- Name: idx_kyc_tier_versions_tenant_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_tier_versions_tenant_status ON public.kyc_tier_versions USING btree (tenant_id, status);


--
-- Name: idx_kyc_tiers_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_tiers_active ON public.kyc_tier_standards USING btree (is_active);


--
-- Name: idx_kyc_verifications_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_verifications_customer ON public.kyc_verifications USING btree (customer_id, requested_at DESC);


--
-- Name: idx_kyc_verifications_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_verifications_provider ON public.kyc_verifications USING btree (provider_name, provider_reference);


--
-- Name: idx_kyc_verifications_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kyc_verifications_status ON public.kyc_verifications USING btree (tenant_id, status);


--
-- Name: idx_login_attempts_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_login_attempts_identifier ON public.login_attempts USING btree (identifier, attempted_at DESC);


--
-- Name: idx_login_attempts_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_login_attempts_ip ON public.login_attempts USING btree (ip_address, attempted_at DESC);


--
-- Name: idx_login_attempts_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_login_attempts_user ON public.login_attempts USING btree (user_id, attempted_at DESC);


--
-- Name: idx_notification_attempt_history; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_attempt_history ON public.notification_delivery_attempts USING btree (tenant_id, notification_id, created_at DESC);


--
-- Name: idx_notification_attempt_retry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_attempt_retry ON public.notification_delivery_attempts USING btree (tenant_id, status, next_retry_at) WHERE ((status)::text = 'RETRYABLE'::text);


--
-- Name: idx_notification_preferences_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_preferences_user ON public.notification_preferences USING btree (user_id);


--
-- Name: idx_notification_templates_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_templates_code ON public.notification_templates USING btree (template_code);


--
-- Name: idx_notifications_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_provider ON public.notifications USING btree (provider_name, provider_reference);


--
-- Name: idx_notifications_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_status ON public.notifications USING btree (tenant_id, status, scheduled_at);


--
-- Name: idx_notifications_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_user ON public.notifications USING btree (user_id, created_at DESC);


--
-- Name: idx_otp_destination; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otp_destination ON public.otp_challenges USING btree (destination, purpose, created_at DESC);


--
-- Name: idx_otp_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otp_expiry ON public.otp_challenges USING btree (expires_at);


--
-- Name: idx_otp_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otp_user ON public.otp_challenges USING btree (user_id, created_at DESC);


--
-- Name: idx_password_reset_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_password_reset_user ON public.password_reset_tokens USING btree (user_id);


--
-- Name: idx_provider_webhook_work; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provider_webhook_work ON public.provider_webhook_events USING btree (status, next_retry_at, received_at) WHERE ((status)::text = ANY (ARRAY[('RECEIVED'::character varying)::text, ('VERIFIED'::character varying)::text, ('FAILED'::character varying)::text]));


--
-- Name: idx_recovery_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_recovery_status ON public.account_recovery_requests USING btree (tenant_id, status);


--
-- Name: idx_recovery_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_recovery_user ON public.account_recovery_requests USING btree (user_id);


--
-- Name: idx_referral_programs_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referral_programs_active ON public.referral_programs USING btree (tenant_id, is_active, start_at, end_at);


--
-- Name: idx_referral_rewards_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referral_rewards_status ON public.referral_rewards USING btree (tenant_id, status);


--
-- Name: idx_referral_rewards_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referral_rewards_user ON public.referral_rewards USING btree (beneficiary_user_id, created_at DESC);


--
-- Name: idx_referrals_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referrals_code ON public.referrals USING btree (tenant_id, referral_code);


--
-- Name: idx_referrals_referred; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referrals_referred ON public.referrals USING btree (referred_user_id);


--
-- Name: idx_referrals_referrer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referrals_referrer ON public.referrals USING btree (referrer_user_id, created_at DESC);


--
-- Name: idx_referrals_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referrals_status ON public.referrals USING btree (tenant_id, status);


--
-- Name: idx_reward_transactions_reward; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reward_transactions_reward ON public.referral_reward_transactions USING btree (reward_id);


--
-- Name: idx_reward_transactions_transaction; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reward_transactions_transaction ON public.referral_reward_transactions USING btree (transaction_id);


--
-- Name: idx_risk_history_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_history_customer ON public.risk_assessment_history USING btree (tenant_id, customer_id, assessed_at DESC);


--
-- Name: idx_user_consents_document; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_consents_document ON public.user_consents USING btree (tenant_id, consent_document_id);


--
-- Name: idx_user_consents_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_consents_tenant ON public.user_consents USING btree (tenant_id);


--
-- Name: idx_user_consents_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_consents_user ON public.user_consents USING btree (user_id, consent_type);


--
-- Name: idx_user_credentials_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_credentials_user ON public.user_credentials USING btree (user_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_user_devices_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_devices_status ON public.user_devices USING btree (user_id, status);


--
-- Name: idx_user_devices_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_devices_user ON public.user_devices USING btree (user_id);


--
-- Name: idx_user_passkeys_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_passkeys_subject ON public.user_passkeys USING btree (subject_type, scope_type, tenant_id, subject_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_user_session_family_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_session_family_active ON public.user_sessions USING btree (tenant_id, token_family_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_user_sessions_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_expiry ON public.user_sessions USING btree (expires_at);


--
-- Name: idx_user_sessions_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_subject ON public.user_sessions USING btree (subject_type, scope_type, tenant_id, subject_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_user_sessions_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_user ON public.user_sessions USING btree (user_id);


--
-- Name: idx_users_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_status ON public.users USING btree (tenant_id, status) WHERE (deleted_at IS NULL);


--
-- Name: idx_users_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant ON public.users USING btree (tenant_id) WHERE (deleted_at IS NULL);


--
-- Name: uq_biometric_reference; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_biometric_reference ON public.user_biometric_credentials USING btree (credential_reference) WHERE (deleted_at IS NULL);


--
-- Name: uq_customer_active_kyc_tier; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_customer_active_kyc_tier ON public.customer_kyc_tiers USING btree (customer_id) WHERE ((status = 'VERIFIED'::public.kyc_status) AND (effective_until IS NULL) AND (deleted_at IS NULL));


--
-- Name: uq_customer_document_number; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_customer_document_number ON public.customer_documents USING btree (tenant_id, document_type, document_number_hash) WHERE ((document_number_hash IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: uq_notification_template; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_notification_template ON public.notification_templates USING btree (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), template_code, channel, version) WHERE (deleted_at IS NULL);


--
-- Name: uq_password_reset_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_password_reset_token ON public.password_reset_tokens USING btree (token_hash);


--
-- Name: uq_referral_referred_program; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_referral_referred_program ON public.referrals USING btree (program_id, referred_user_id) WHERE (referred_user_id IS NOT NULL);


--
-- Name: uq_referral_reward_beneficiary_type; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_referral_reward_beneficiary_type ON public.referral_rewards USING btree (referral_id, beneficiary_user_id, reward_type);


--
-- Name: uq_user_credential_type_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_user_credential_type_active ON public.user_credentials USING btree (user_id, credential_type) WHERE (deleted_at IS NULL);


--
-- Name: uq_user_device_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_user_device_active ON public.user_devices USING btree (user_id, device_identifier) WHERE (deleted_at IS NULL);


--
-- Name: uq_user_passkey_credential; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_user_passkey_credential ON public.user_passkeys USING btree (credential_id) WHERE (deleted_at IS NULL);


--
-- Name: uq_user_session_family_rotation; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_user_session_family_rotation ON public.user_sessions USING btree (token_family_id, rotation_sequence);


--
-- Name: uq_user_sessions_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_user_sessions_token ON public.user_sessions USING btree (session_token_hash);


--
-- Name: uq_users_tenant_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_users_tenant_email ON public.users USING btree (tenant_id, lower((email)::text)) WHERE ((email IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: uq_users_tenant_email_normalized; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_users_tenant_email_normalized ON public.users USING btree (tenant_id, email_normalized) WHERE ((email_normalized IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: uq_users_tenant_phone; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_users_tenant_phone ON public.users USING btree (tenant_id, phone) WHERE ((phone IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: uq_users_tenant_phone_normalized; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_users_tenant_phone_normalized ON public.users USING btree (tenant_id, phone_normalized) WHERE ((phone_normalized IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: uq_users_tenant_referral_code; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_users_tenant_referral_code ON public.users USING btree (tenant_id, referral_code) WHERE ((referral_code IS NOT NULL) AND (deleted_at IS NULL));


--
-- Name: account_recovery_requests trg_account_recovery_requests_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_account_recovery_requests_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.account_recovery_requests FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: account_recovery_requests trg_account_recovery_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_account_recovery_updated_at BEFORE UPDATE ON public.account_recovery_requests FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: aml_profiles trg_aml_profiles_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_aml_profiles_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.aml_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: aml_profiles trg_aml_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_aml_profiles_updated_at BEFORE UPDATE ON public.aml_profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: aml_screening_checks trg_aml_screening_checks_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_aml_screening_checks_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.aml_screening_checks FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: aml_screening_results trg_aml_screening_results_screening_check_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_aml_screening_results_screening_check_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, screening_check_id ON public.aml_screening_results FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('aml_screening_checks', 'id', 'screening_check_id');


--
-- Name: auth_audit_events trg_auth_audit_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_auth_audit_immutable BEFORE DELETE OR UPDATE ON public.auth_audit_events FOR EACH ROW EXECUTE FUNCTION public.reject_auth_audit_mutation();


--
-- Name: credential_history trg_credential_history_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_credential_history_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.credential_history FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: customer_addresses trg_customer_addresses_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_addresses_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.customer_addresses FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: customer_addresses trg_customer_addresses_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_addresses_updated_at BEFORE UPDATE ON public.customer_addresses FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: customer_documents trg_customer_documents_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_documents_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.customer_documents FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: customer_documents trg_customer_documents_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_documents_updated_at BEFORE UPDATE ON public.customer_documents FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: customer_kyc_tiers trg_customer_kyc_tiers_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_kyc_tiers_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.customer_kyc_tiers FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: customer_kyc_tiers trg_customer_kyc_tiers_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_kyc_tiers_updated_at BEFORE UPDATE ON public.customer_kyc_tiers FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: customer_merge_history trg_customer_merge_history_source_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_merge_history_source_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, source_customer_id ON public.customer_merge_history FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'source_customer_id');


--
-- Name: customer_merge_history trg_customer_merge_history_source_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_merge_history_source_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, source_user_id ON public.customer_merge_history FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'source_user_id');


--
-- Name: customer_merge_history trg_customer_merge_history_target_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_merge_history_target_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, target_customer_id ON public.customer_merge_history FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'target_customer_id');


--
-- Name: customer_merge_history trg_customer_merge_history_target_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_merge_history_target_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, target_user_id ON public.customer_merge_history FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'target_user_id');


--
-- Name: customer_profiles trg_customer_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_profiles_updated_at BEFORE UPDATE ON public.customer_profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: customer_profiles trg_customer_profiles_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_profiles_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.customer_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: customer_risk_profiles trg_customer_risk_profiles_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_risk_profiles_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.customer_risk_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: customer_risk_profiles trg_customer_risk_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_risk_profiles_updated_at BEFORE UPDATE ON public.customer_risk_profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: customer_status_history trg_customer_status_history_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_customer_status_history_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.customer_status_history FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: data_erasure_requests trg_data_erasure_requests_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_data_erasure_requests_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.data_erasure_requests FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: data_erasure_requests trg_data_erasure_requests_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_data_erasure_requests_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.data_erasure_requests FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: data_erasure_requests trg_data_erasure_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_data_erasure_updated_at BEFORE UPDATE ON public.data_erasure_requests FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: fraud_flag_events trg_fraud_flag_events_fraud_flag_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_fraud_flag_events_fraud_flag_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, fraud_flag_id ON public.fraud_flag_events FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('fraud_flags', 'id', 'fraud_flag_id');


--
-- Name: fraud_flags trg_fraud_flags_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_fraud_flags_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.fraud_flags FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: fraud_flags trg_fraud_flags_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_fraud_flags_updated_at BEFORE UPDATE ON public.fraud_flags FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: fraud_flags trg_fraud_flags_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_fraud_flags_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.fraud_flags FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: kyc_profiles trg_kyc_profiles_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_kyc_profiles_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.kyc_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: kyc_profiles trg_kyc_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_kyc_profiles_updated_at BEFORE UPDATE ON public.kyc_profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: kyc_tier_versions trg_kyc_tier_version_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_kyc_tier_version_immutable BEFORE DELETE OR UPDATE ON public.kyc_tier_versions FOR EACH ROW EXECUTE FUNCTION public.prevent_published_record_mutation();


--
-- Name: kyc_tier_standards trg_kyc_tiers_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_kyc_tiers_updated_at BEFORE UPDATE ON public.kyc_tier_standards FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: kyc_verification_results trg_kyc_verification_results_verification_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_kyc_verification_results_verification_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, verification_id ON public.kyc_verification_results FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('kyc_verifications', 'id', 'verification_id');


--
-- Name: kyc_verifications trg_kyc_verifications_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_kyc_verifications_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.kyc_verifications FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: kyc_verifications trg_kyc_verifications_document_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_kyc_verifications_document_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, document_id ON public.kyc_verifications FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_documents', 'id', 'document_id');


--
-- Name: login_attempts trg_login_attempts_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_login_attempts_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.login_attempts FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: notification_delivery_attempts trg_notification_attempt_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_notification_attempt_immutable BEFORE DELETE OR UPDATE ON public.notification_delivery_attempts FOR EACH ROW EXECUTE FUNCTION public.reject_completed_notification_attempt_mutation();


--
-- Name: notification_preferences trg_notification_preferences_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_notification_preferences_updated_at BEFORE UPDATE ON public.notification_preferences FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: notification_preferences trg_notification_preferences_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_notification_preferences_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.notification_preferences FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: notification_templates trg_notification_templates_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_notification_templates_updated_at BEFORE UPDATE ON public.notification_templates FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: notifications trg_notifications_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_notifications_updated_at BEFORE UPDATE ON public.notifications FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: notifications trg_notifications_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_notifications_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.notifications FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: otp_challenges trg_otp_challenges_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_otp_challenges_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.otp_challenges FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: password_reset_tokens trg_password_reset_tokens_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_password_reset_tokens_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.password_reset_tokens FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: referral_programs trg_referral_programs_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referral_programs_updated_at BEFORE UPDATE ON public.referral_programs FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: referral_reward_transactions trg_referral_reward_transactions_reward_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referral_reward_transactions_reward_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, reward_id ON public.referral_reward_transactions FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('referral_rewards', 'id', 'reward_id');


--
-- Name: referral_rewards trg_referral_rewards_beneficiary_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referral_rewards_beneficiary_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, beneficiary_user_id ON public.referral_rewards FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'beneficiary_user_id');


--
-- Name: referral_rewards trg_referral_rewards_referral_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referral_rewards_referral_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, referral_id ON public.referral_rewards FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('referrals', 'id', 'referral_id');


--
-- Name: referral_rewards trg_referral_rewards_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referral_rewards_updated_at BEFORE UPDATE ON public.referral_rewards FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: referrals trg_referrals_program_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referrals_program_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, program_id ON public.referrals FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('referral_programs', 'id', 'program_id');


--
-- Name: referrals trg_referrals_referred_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referrals_referred_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, referred_user_id ON public.referrals FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'referred_user_id');


--
-- Name: referrals trg_referrals_referrer_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referrals_referrer_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, referrer_user_id ON public.referrals FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'referrer_user_id');


--
-- Name: referrals trg_referrals_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_referrals_updated_at BEFORE UPDATE ON public.referrals FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: risk_assessment_history trg_risk_assessment_history_customer_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_risk_assessment_history_customer_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON public.risk_assessment_history FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('customer_profiles', 'id', 'customer_id');


--
-- Name: user_2fa_methods trg_user_2fa_methods_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_2fa_methods_updated_at BEFORE UPDATE ON public.user_2fa_methods FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: user_2fa_methods trg_user_2fa_methods_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_2fa_methods_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.user_2fa_methods FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: user_biometric_credentials trg_user_biometric_credentials_device_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_biometric_credentials_device_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, device_id ON public.user_biometric_credentials FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('user_devices', 'id', 'device_id');


--
-- Name: user_biometric_credentials trg_user_biometric_credentials_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_biometric_credentials_updated_at BEFORE UPDATE ON public.user_biometric_credentials FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: user_biometric_credentials trg_user_biometric_credentials_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_biometric_credentials_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.user_biometric_credentials FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: user_consents trg_user_consents_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_consents_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.user_consents FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: user_credentials trg_user_credentials_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_credentials_updated_at BEFORE UPDATE ON public.user_credentials FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: user_credentials trg_user_credentials_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_credentials_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.user_credentials FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: user_devices trg_user_devices_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_devices_updated_at BEFORE UPDATE ON public.user_devices FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: user_devices trg_user_devices_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_devices_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.user_devices FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: user_passkeys trg_user_passkeys_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_passkeys_updated_at BEFORE UPDATE ON public.user_passkeys FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: user_passkeys trg_user_passkeys_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_passkeys_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.user_passkeys FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: user_sessions trg_user_sessions_device_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_sessions_device_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, device_id ON public.user_sessions FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('user_devices', 'id', 'device_id');


--
-- Name: user_sessions trg_user_sessions_user_id_tenant_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_user_sessions_user_id_tenant_guard BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.user_sessions FOR EACH ROW EXECUTE FUNCTION public.enforce_parent_tenant('users', 'id', 'user_id');


--
-- Name: users trg_users_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: customer_documents customer_documents_consent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_documents
    ADD CONSTRAINT customer_documents_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.user_consents(id);


--
-- Name: customer_kyc_tiers customer_kyc_tiers_kyc_tier_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_kyc_tiers
    ADD CONSTRAINT customer_kyc_tiers_kyc_tier_version_id_fkey FOREIGN KEY (kyc_tier_version_id) REFERENCES public.kyc_tier_versions(id);


--
-- Name: user_2fa_methods fk_2fa_customer_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_2fa_methods
    ADD CONSTRAINT fk_2fa_customer_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: aml_screening_checks fk_aml_check_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aml_screening_checks
    ADD CONSTRAINT fk_aml_check_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: aml_profiles fk_aml_profile_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aml_profiles
    ADD CONSTRAINT fk_aml_profile_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: aml_screening_results fk_aml_result_check; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aml_screening_results
    ADD CONSTRAINT fk_aml_result_check FOREIGN KEY (screening_check_id) REFERENCES public.aml_screening_checks(id) ON DELETE CASCADE;


--
-- Name: auth_audit_events fk_auth_audit_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_audit_events
    ADD CONSTRAINT fk_auth_audit_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: user_biometric_credentials fk_biometric_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_biometric_credentials
    ADD CONSTRAINT fk_biometric_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: credential_history fk_credential_history_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential_history
    ADD CONSTRAINT fk_credential_history_source FOREIGN KEY (replaced_credential_id) REFERENCES public.user_credentials(id) ON DELETE SET NULL;


--
-- Name: credential_history fk_credential_history_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential_history
    ADD CONSTRAINT fk_credential_history_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: customer_addresses fk_customer_address_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_addresses
    ADD CONSTRAINT fk_customer_address_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: customer_documents fk_customer_document_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_documents
    ADD CONSTRAINT fk_customer_document_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: customer_kyc_tiers fk_customer_kyc_tier_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_kyc_tiers
    ADD CONSTRAINT fk_customer_kyc_tier_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: customer_profiles fk_customer_profile_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_profiles
    ADD CONSTRAINT fk_customer_profile_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: customer_risk_profiles fk_customer_risk_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_risk_profiles
    ADD CONSTRAINT fk_customer_risk_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: data_erasure_requests fk_erasure_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_erasure_requests
    ADD CONSTRAINT fk_erasure_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE SET NULL;


--
-- Name: data_erasure_requests fk_erasure_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_erasure_requests
    ADD CONSTRAINT fk_erasure_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: fraud_flag_events fk_fraud_event_flag; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fraud_flag_events
    ADD CONSTRAINT fk_fraud_event_flag FOREIGN KEY (fraud_flag_id) REFERENCES public.fraud_flags(id) ON DELETE CASCADE;


--
-- Name: fraud_flags fk_fraud_flag_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fraud_flags
    ADD CONSTRAINT fk_fraud_flag_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE SET NULL;


--
-- Name: fraud_flags fk_fraud_flag_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fraud_flags
    ADD CONSTRAINT fk_fraud_flag_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: kyc_profiles fk_kyc_profile_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_profiles
    ADD CONSTRAINT fk_kyc_profile_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: kyc_verification_results fk_kyc_result_verification; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_verification_results
    ADD CONSTRAINT fk_kyc_result_verification FOREIGN KEY (verification_id) REFERENCES public.kyc_verifications(id) ON DELETE CASCADE;


--
-- Name: kyc_verifications fk_kyc_verification_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_verifications
    ADD CONSTRAINT fk_kyc_verification_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE CASCADE;


--
-- Name: kyc_verifications fk_kyc_verification_document; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_verifications
    ADD CONSTRAINT fk_kyc_verification_document FOREIGN KEY (document_id) REFERENCES public.customer_documents(id) ON DELETE SET NULL;


--
-- Name: customer_merge_history fk_merge_source_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_merge_history
    ADD CONSTRAINT fk_merge_source_customer FOREIGN KEY (source_customer_id) REFERENCES public.customer_profiles(id) ON DELETE SET NULL;


--
-- Name: customer_merge_history fk_merge_source_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_merge_history
    ADD CONSTRAINT fk_merge_source_user FOREIGN KEY (source_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: customer_merge_history fk_merge_target_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_merge_history
    ADD CONSTRAINT fk_merge_target_customer FOREIGN KEY (target_customer_id) REFERENCES public.customer_profiles(id) ON DELETE RESTRICT;


--
-- Name: customer_merge_history fk_merge_target_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_merge_history
    ADD CONSTRAINT fk_merge_target_user FOREIGN KEY (target_user_id) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: notification_preferences fk_notification_preferences_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT fk_notification_preferences_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: notifications fk_notification_template; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT fk_notification_template FOREIGN KEY (template_id) REFERENCES public.notification_templates(id) ON DELETE SET NULL;


--
-- Name: notifications fk_notification_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT fk_notification_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: otp_challenges fk_otp_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.otp_challenges
    ADD CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: password_reset_tokens fk_password_reset_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: account_recovery_requests fk_recovery_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_recovery_requests
    ADD CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: referrals fk_referral_program; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT fk_referral_program FOREIGN KEY (program_id) REFERENCES public.referral_programs(id);


--
-- Name: referrals fk_referral_referred; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT fk_referral_referred FOREIGN KEY (referred_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: referrals fk_referral_referrer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT fk_referral_referrer FOREIGN KEY (referrer_user_id) REFERENCES public.users(id);


--
-- Name: referral_rewards fk_referral_reward_referral; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referral_rewards
    ADD CONSTRAINT fk_referral_reward_referral FOREIGN KEY (referral_id) REFERENCES public.referrals(id) ON DELETE CASCADE;


--
-- Name: referral_rewards fk_referral_reward_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referral_rewards
    ADD CONSTRAINT fk_referral_reward_user FOREIGN KEY (beneficiary_user_id) REFERENCES public.users(id);


--
-- Name: referral_reward_transactions fk_reward_transaction_reward; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referral_reward_transactions
    ADD CONSTRAINT fk_reward_transaction_reward FOREIGN KEY (reward_id) REFERENCES public.referral_rewards(id) ON DELETE CASCADE;


--
-- Name: risk_assessment_history fk_risk_history_customer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_assessment_history
    ADD CONSTRAINT fk_risk_history_customer FOREIGN KEY (customer_id) REFERENCES public.customer_profiles(id) ON DELETE RESTRICT;


--
-- Name: user_consents fk_user_consents_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_consents
    ADD CONSTRAINT fk_user_consents_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_credentials fk_user_credentials_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_credentials
    ADD CONSTRAINT fk_user_credentials_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_devices fk_user_devices_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT fk_user_devices_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_passkeys fk_user_passkeys_customer_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_passkeys
    ADD CONSTRAINT fk_user_passkeys_customer_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_sessions fk_user_sessions_customer_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT fk_user_sessions_customer_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: identity_verification_evidence identity_verification_evidence_consent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_verification_evidence
    ADD CONSTRAINT identity_verification_evidence_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.user_consents(id);


--
-- Name: identity_verification_evidence identity_verification_evidence_verification_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_verification_evidence
    ADD CONSTRAINT identity_verification_evidence_verification_id_fkey FOREIGN KEY (verification_id) REFERENCES public.kyc_verifications(id);


--
-- Name: kyc_tier_versions kyc_tier_versions_standard_tier_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_tier_versions
    ADD CONSTRAINT kyc_tier_versions_standard_tier_id_fkey FOREIGN KEY (standard_tier_id) REFERENCES public.kyc_tier_standards(id);


--
-- Name: kyc_verifications kyc_verifications_consent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kyc_verifications
    ADD CONSTRAINT kyc_verifications_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.user_consents(id);


--
-- Name: notification_delivery_attempts notification_delivery_attempts_notification_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_delivery_attempts
    ADD CONSTRAINT notification_delivery_attempts_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES public.notifications(id);


--
-- Name: user_sessions user_sessions_replaced_by_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_replaced_by_session_id_fkey FOREIGN KEY (replaced_by_session_id) REFERENCES public.user_sessions(id);


--
-- Name: account_recovery_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.account_recovery_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: aml_profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.aml_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: aml_screening_checks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.aml_screening_checks ENABLE ROW LEVEL SECURITY;

--
-- Name: aml_screening_results; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.aml_screening_results ENABLE ROW LEVEL SECURITY;

--
-- Name: auth_audit_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.auth_audit_events ENABLE ROW LEVEL SECURITY;

--
-- Name: auth_customer_inbox_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.auth_customer_inbox_events ENABLE ROW LEVEL SECURITY;

--
-- Name: auth_customer_outbox_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.auth_customer_outbox_events ENABLE ROW LEVEL SECURITY;

--
-- Name: authentication_challenges; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.authentication_challenges ENABLE ROW LEVEL SECURITY;

--
-- Name: credential_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.credential_history ENABLE ROW LEVEL SECURITY;

--
-- Name: customer_addresses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.customer_addresses ENABLE ROW LEVEL SECURITY;

--
-- Name: customer_documents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.customer_documents ENABLE ROW LEVEL SECURITY;

--
-- Name: customer_kyc_tiers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.customer_kyc_tiers ENABLE ROW LEVEL SECURITY;

--
-- Name: customer_merge_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.customer_merge_history ENABLE ROW LEVEL SECURITY;

--
-- Name: customer_profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.customer_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: customer_risk_profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.customer_risk_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: customer_status_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.customer_status_history ENABLE ROW LEVEL SECURITY;

--
-- Name: data_erasure_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.data_erasure_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: fraud_flag_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.fraud_flag_events ENABLE ROW LEVEL SECURITY;

--
-- Name: fraud_flags; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.fraud_flags ENABLE ROW LEVEL SECURITY;

--
-- Name: idempotency_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.idempotency_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: identity_verification_evidence; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.identity_verification_evidence ENABLE ROW LEVEL SECURITY;

--
-- Name: kyc_profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.kyc_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: kyc_tier_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.kyc_tier_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: kyc_verification_results; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.kyc_verification_results ENABLE ROW LEVEL SECURITY;

--
-- Name: kyc_verifications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.kyc_verifications ENABLE ROW LEVEL SECURITY;

--
-- Name: login_attempts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.login_attempts ENABLE ROW LEVEL SECURITY;

--
-- Name: notification_delivery_attempts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notification_delivery_attempts ENABLE ROW LEVEL SECURITY;

--
-- Name: notification_preferences; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notification_preferences ENABLE ROW LEVEL SECURITY;

--
-- Name: notification_templates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notification_templates ENABLE ROW LEVEL SECURITY;

--
-- Name: notification_templates notification_templates_read_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY notification_templates_read_policy ON public.notification_templates FOR SELECT USING (((tenant_id IS NULL) OR (tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: notification_templates notification_templates_write_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY notification_templates_write_policy ON public.notification_templates USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: notifications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

--
-- Name: otp_challenges; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.otp_challenges ENABLE ROW LEVEL SECURITY;

--
-- Name: password_reset_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.password_reset_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: provider_webhook_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.provider_webhook_events ENABLE ROW LEVEL SECURITY;

--
-- Name: referral_programs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.referral_programs ENABLE ROW LEVEL SECURITY;

--
-- Name: referral_reward_transactions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.referral_reward_transactions ENABLE ROW LEVEL SECURITY;

--
-- Name: referral_rewards; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.referral_rewards ENABLE ROW LEVEL SECURITY;

--
-- Name: referrals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.referrals ENABLE ROW LEVEL SECURITY;

--
-- Name: risk_assessment_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.risk_assessment_history ENABLE ROW LEVEL SECURITY;

--
-- Name: account_recovery_requests tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.account_recovery_requests TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: aml_profiles tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.aml_profiles TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: aml_screening_checks tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.aml_screening_checks TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: aml_screening_results tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.aml_screening_results TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: auth_audit_events tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.auth_audit_events TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: auth_customer_inbox_events tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.auth_customer_inbox_events TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: auth_customer_outbox_events tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.auth_customer_outbox_events TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: authentication_challenges tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.authentication_challenges TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text)))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text))));


--
-- Name: credential_history tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.credential_history TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: customer_addresses tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.customer_addresses TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: customer_documents tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.customer_documents TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: customer_kyc_tiers tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.customer_kyc_tiers TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: customer_merge_history tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.customer_merge_history TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: customer_profiles tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.customer_profiles TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: customer_risk_profiles tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.customer_risk_profiles TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: customer_status_history tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.customer_status_history TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: data_erasure_requests tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.data_erasure_requests TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: fraud_flag_events tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.fraud_flag_events TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: fraud_flags tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.fraud_flags TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: idempotency_keys tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.idempotency_keys TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: identity_verification_evidence tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.identity_verification_evidence TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: kyc_profiles tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.kyc_profiles TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: kyc_tier_versions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.kyc_tier_versions TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: kyc_verification_results tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.kyc_verification_results TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: kyc_verifications tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.kyc_verifications TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: login_attempts tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.login_attempts TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: notification_delivery_attempts tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.notification_delivery_attempts TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: notification_preferences tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.notification_preferences TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: notifications tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.notifications TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: otp_challenges tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.otp_challenges TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: password_reset_tokens tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.password_reset_tokens TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: provider_webhook_events tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.provider_webhook_events TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: referral_programs tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.referral_programs TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: referral_reward_transactions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.referral_reward_transactions TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: referral_rewards tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.referral_rewards TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: referrals tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.referrals TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: risk_assessment_history tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.risk_assessment_history TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: user_2fa_methods tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_2fa_methods TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text)))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text))));


--
-- Name: user_biometric_credentials tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_biometric_credentials TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: user_consents tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_consents TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: user_credentials tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_credentials TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: user_devices tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_devices TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: user_passkeys tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_passkeys TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text)))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text))));


--
-- Name: user_sessions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_sessions TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text)))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND ((scope_type)::text = 'PLATFORM'::text) AND (current_setting('app.platform_scope'::text, true) = 'true'::text))));


--
-- Name: users tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.users TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));


--
-- Name: user_2fa_methods; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_2fa_methods ENABLE ROW LEVEL SECURITY;

--
-- Name: user_biometric_credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_biometric_credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: user_consents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_consents ENABLE ROW LEVEL SECURITY;

--
-- Name: user_credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: user_devices; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;

--
-- Name: user_passkeys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_passkeys ENABLE ROW LEVEL SECURITY;

--
-- Name: user_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: users; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
--
