CREATE OR REPLACE FUNCTION is_active_user()
RETURNS TRIGGER AS $$
DECLARE 
	user_name varchar(100);
BEGIN
    SELECT u."name" INTO user_name 
    FROM "user" u
    WHERE u.user_id = NEW.user_fk AND u.is_active = false;

    IF user_name IS NOT NULL THEN
        RAISE EXCEPTION 'No se puede INSERT, UPDATE o DELETE el registro. El usuario referenciado (%) no está activo.', user_name;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------

-- VISITOR
CREATE TRIGGER trg_is_active_user_for_visitor
BEFORE INSERT OR UPDATE ON "visitor"
FOR EACH ROW
EXECUTE FUNCTION is_active_user();