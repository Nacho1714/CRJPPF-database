CREATE OR REPLACE FUNCTION validate_profile()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.profile IS NOT NULL THEN
        IF LENGTH(NEW.profile) <> 4 THEN
            RAISE EXCEPTION 'El perfil "%" es invalido (MAX 4 letras).', NEW.profile;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- USER
CREATE TRIGGER trg_insert_user_validate_profile
BEFORE INSERT ON "user"
FOR EACH ROW
EXECUTE FUNCTION validate_profile();

CREATE TRIGGER trg_update_user_validate_profile
BEFORE UPDATE ON "user"
FOR EACH ROW
WHEN (NEW.profile <> OLD.profile)
EXECUTE FUNCTION validate_profile();