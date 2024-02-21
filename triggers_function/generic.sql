-- refresh_updated_at_column: Actualiza el campo updated_at con la fecha actual
CREATE OR REPLACE FUNCTION refresh_updated_at_column()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
    END;
$$ LANGUAGE plpgsql;

-- ejecucion automatica de la funcion refresh_updated_at_column
DO $$ 
    DECLARE
        table_name_var text;
    BEGIN
        FOR table_name_var IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE') LOOP
            EXECUTE 'CREATE TRIGGER "' || table_name_var || '_refresh_trigger"
                    BEFORE UPDATE ON "' || table_name_var || '"
                    FOR EACH ROW EXECUTE FUNCTION refresh_updated_at_column();';
        END LOOP;
END $$;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
-- proteger created_at - ejecutado
CREATE OR REPLACE FUNCTION prevent_modification_created_at()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'No se permite modificar el campo "created_at"';
    END;
$$ LANGUAGE plpgsql;

-- ejecucion automatica de la funcion prevent_modification_created_at
DO $$ 
    DECLARE
        table_name_var text;
    BEGIN
        FOR table_name_var IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE') LOOP
            EXECUTE 'CREATE TRIGGER "' || table_name_var || '_prevent_modification"
                    BEFORE UPDATE ON "' || table_name_var || '"
                    FOR EACH ROW WHEN (NEW.created_at <> OLD.created_at)
                    EXECUTE FUNCTION prevent_modification_created_at();';
        END LOOP;
END $$;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION name_directorate_has_sector()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
    DECLARE
        directorate_name 	VARCHAR(40);
        sector_name 		VARCHAR(40);
    BEGIN
    
    	IF NEW.name <> OLD.name THEN RETURN NEW; END IF;
    	
    	SELECT d.name
    	INTO directorate_name
    	FROM directorate d
    	WHERE d.directorate_id = NEW.directorate_fk;

		SELECT s.name
		INTO sector_name
		FROM sector s
		WHERE s.sector_id = NEW.sector_fk;

		NEW.name = directorate_name || ' - ' || sector_name;

        RETURN NEW;
    END;
$function$;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION convert_to_uppercase_directorate()
    RETURNS TRIGGER AS $$
BEGIN
    
    IF NEW.name IS NOT NULL THEN NEW.name := UPPER(TRIM(NEW.name)); END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION convert_to_uppercase_sector()
    RETURNS TRIGGER AS $$
BEGIN
    
    IF NEW.name IS NOT NULL THEN NEW.name := UPPER(TRIM(NEW.name)); END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION convert_to_uppercase_directorate_has_sector()
    RETURNS TRIGGER AS $$
BEGIN
    
    IF NEW.name IS NOT NULL THEN NEW.name := UPPER(TRIM(NEW.name)); END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION convert_to_uppercase_employee()
    RETURNS TRIGGER AS $$
BEGIN
    
    IF NEW.name IS NOT NULL THEN NEW.name := UPPER(TRIM(NEW.name)); END IF;
    IF NEW.last_name IS NOT NULL THEN NEW.last_name := UPPER(TRIM(NEW.last_name)); END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION convert_to_uppercase_position()
    RETURNS TRIGGER AS $$
BEGIN
    
    IF NEW.name IS NOT NULL THEN NEW.name := UPPER(TRIM(NEW.name)); END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION convert_to_uppercase_user()
    RETURNS TRIGGER AS $$
BEGIN
    
    IF NEW.name IS NOT NULL THEN NEW.name := UPPER(TRIM(NEW.name)); END IF;
    IF NEW.last_name IS NOT NULL THEN NEW.last_name := UPPER(TRIM(NEW.last_name)); END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION convert_to_uppercase_visitor()
    RETURNS TRIGGER AS $$
BEGIN
    
    IF NEW.name IS NOT NULL THEN NEW.name := UPPER(TRIM(NEW.name)); END IF;
    IF NEW.last_name IS NOT NULL THEN NEW.last_name := UPPER(TRIM(NEW.last_name)); END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

--########################################################################################################
-- TRIGGERS ##############################################################################################
--########################################################################################################

----------------------------------------------------------------------------------------------------------
-- directorate_has_sector --------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE TRIGGER trg_insert_name_directorate_has_sector
BEFORE INSERT ON "directorate_has_sector"
FOR EACH ROW
EXECUTE FUNCTION name_directorate_has_sector();

CREATE TRIGGER trg_update_name_directorate_has_sector
BEFORE UPDATE ON "directorate_has_sector"
FOR EACH ROW
WHEN (NEW.directorate_fk <> OLD.directorate_fk OR NEW.sector_fk <> OLD.sector_fk)
EXECUTE FUNCTION name_directorate_has_sector();

CREATE TRIGGER trg_insert_uppercase_directorate_has_sector
BEFORE INSERT ON "directorate_has_sector"
FOR EACH ROW
EXECUTE FUNCTION convert_to_uppercase_directorate_has_sector();

CREATE TRIGGER trg_update_uppercase_directorate_has_sector
BEFORE UPDATE ON "directorate_has_sector"
FOR EACH ROW
WHEN (NEW.name <> OLD.name)
EXECUTE FUNCTION convert_to_uppercase_directorate_has_sector();
----------------------------------------------------------------------------------------------------------
-- directorate -------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE TRIGGER trg_insert_uppercase_directorate
BEFORE INSERT ON "directorate"
FOR EACH ROW
EXECUTE FUNCTION convert_to_uppercase_directorate();

CREATE TRIGGER trg_update_uppercase_directorate
BEFORE UPDATE ON "directorate"
FOR EACH ROW
WHEN (NEW.name <> OLD.name)
EXECUTE FUNCTION convert_to_uppercase_directorate();
----------------------------------------------------------------------------------------------------------
-- sector ------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE TRIGGER trg_insert_uppercase_sector
BEFORE INSERT ON "sector"
FOR EACH ROW
EXECUTE FUNCTION convert_to_uppercase_sector();

CREATE TRIGGER trg_update_uppercase_sector
BEFORE UPDATE ON "sector"
FOR EACH ROW
WHEN (NEW.name <> OLD.name)
EXECUTE FUNCTION convert_to_uppercase_sector();
----------------------------------------------------------------------------------------------------------
-- employee ----------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE TRIGGER trg_insert_uppercase_employee
BEFORE INSERT ON "employee"
FOR EACH ROW
EXECUTE FUNCTION convert_to_uppercase_employee();

CREATE TRIGGER trg_update_uppercase_employee
BEFORE UPDATE ON "employee"
FOR EACH ROW
WHEN (NEW.name <> OLD.name OR NEW.last_name <> OLD.last_name)
EXECUTE FUNCTION convert_to_uppercase_employee();
----------------------------------------------------------------------------------------------------------
-- position ----------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE TRIGGER trg_insert_uppercase_position
BEFORE INSERT ON "position"
FOR EACH ROW
EXECUTE FUNCTION convert_to_uppercase_position();

CREATE TRIGGER trg_update_uppercase_position
BEFORE UPDATE ON "position"
FOR EACH ROW
WHEN (NEW.name <> OLD.name)
EXECUTE FUNCTION convert_to_uppercase_position();
----------------------------------------------------------------------------------------------------------
-- user --------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE TRIGGER trg_insert_uppercase_user
BEFORE INSERT ON "user"
FOR EACH ROW
EXECUTE FUNCTION convert_to_uppercase_user();

CREATE TRIGGER trg_update_uppercase_user
BEFORE UPDATE ON "user"
FOR EACH ROW
WHEN (NEW.name <> OLD.name OR NEW.last_name <> OLD.last_name)
EXECUTE FUNCTION convert_to_uppercase_user();
----------------------------------------------------------------------------------------------------------
-- visitor -----------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE TRIGGER trg_insert_uppercase_visitor
BEFORE INSERT ON "visitor"
FOR EACH ROW
EXECUTE FUNCTION convert_to_uppercase_visitor();

CREATE TRIGGER trg_update_uppercase_visitor
BEFORE UPDATE ON "visitor"
FOR EACH ROW
WHEN (NEW.name <> OLD.name OR NEW.last_name <> OLD.last_name)
EXECUTE FUNCTION convert_to_uppercase_visitor();