-- =============================================================================
-- Schema för säker utskriftsspooler
-- =============================================================================

CREATE TABLE IF NOT EXISTS print_jobs (
    -- Identitet
    id              UUID                        PRIMARY KEY,
    cups_job_id     INTEGER,

    -- Ägare
    user_upn        VARCHAR(255)                NOT NULL,

    -- Jobbmetadata
    title           VARCHAR(500)                NOT NULL DEFAULT '',
    copies          INTEGER                     NOT NULL DEFAULT 1,
    options         TEXT                        NOT NULL DEFAULT '{}',

    -- Lagring
    s3_key          VARCHAR(1000)               NOT NULL,
    encrypted_size  BIGINT                      NOT NULL,

    -- Tider
    submitted_at    TIMESTAMP WITH TIME ZONE    NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE    NOT NULL DEFAULT NOW() + INTERVAL '48 hours',
    retrieved_at    TIMESTAMP WITH TIME ZONE,

    -- Status och spårning
    status          VARCHAR(50)                 NOT NULL DEFAULT 'pending',
    retrieved_by    VARCHAR(100),   -- terminal-id som hämtade jobbet

    CONSTRAINT status_valid CHECK (status IN ('pending', 'retrieved', 'cancelled', 'expired'))
);

-- Index för vanliga frågor
CREATE INDEX IF NOT EXISTS idx_jobs_user_pending
    ON print_jobs (user_upn, submitted_at DESC)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_jobs_expires
    ON print_jobs (expires_at)
    WHERE status = 'pending';

-- =============================================================================
-- Funktion: markera utgångna jobb och returnera S3-nycklar att rensa
-- Kallas av ett schemalagt jobb (cron/CronJob i K8s)
-- =============================================================================
CREATE OR REPLACE FUNCTION expire_old_jobs()
RETURNS TABLE (s3_key VARCHAR) AS $$
BEGIN
    RETURN QUERY
        UPDATE print_jobs
        SET    status = 'expired'
        WHERE  status IN ('pending', 'cancelled')
          AND  expires_at < NOW()
        RETURNING print_jobs.s3_key;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- View: aktiva jobb per användare (används av tunna terminalen)
-- =============================================================================
-- ALTER TABLE print_jobs ADD COLUMN options TEXT NOT NULL DEFAULT '{}';

CREATE OR REPLACE VIEW pending_jobs AS
    SELECT
        id,
        user_upn,
        title,
        copies,
        options,
        s3_key,
        encrypted_size,
        submitted_at,
        expires_at
    FROM print_jobs
    WHERE status = 'pending'
      AND expires_at > NOW()
    ORDER BY submitted_at DESC;

-- =============================================================================
-- Kommentarer
-- =============================================================================
COMMENT ON TABLE  print_jobs              IS 'Krypterade utskriftsjobb i S3-spoolern';
COMMENT ON COLUMN print_jobs.id           IS 'Unikt jobb-ID (UUID), används som del av S3-nyckel';
COMMENT ON COLUMN print_jobs.user_upn     IS 'Ägarens UPN, t.ex. anna@company.com';
COMMENT ON COLUMN print_jobs.s3_key       IS 'S3-objektnyckel för krypterad jobbfil (CMS)';
COMMENT ON COLUMN print_jobs.encrypted_size IS 'Storlek på krypterad fil i bytes';
COMMENT ON COLUMN print_jobs.status       IS 'pending|retrieved|cancelled|expired';
COMMENT ON COLUMN print_jobs.retrieved_by IS 'Terminal-ID som hämtade och decrypterade jobbet';
