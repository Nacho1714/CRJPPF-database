DROP TYPE IF EXISTS "document_options";
CREATE TYPE "document_options" AS ENUM (
    'DNI',
    'LE',
    'LC',
    'PAS'
);

-----------------------------------------------------------------------------------------------
-- USER
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "user" CASCADE;
CREATE TABLE "user" (
    "user_id"               INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "name"                  VARCHAR(100)        NOT NULL,
    "last_name"             VARCHAR(100)        NOT NULL,
    "profile"               CHAR(4)      UNIQUE NOT NULL,
    "password"              VARCHAR(255)        NOT NULL,
    "last_login"            TIMESTAMP,           
    "is_active"             BOOLEAN             NOT NULL    DEFAULT TRUE,
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP

    CHECK ("name" ~ '^[A-Za-z\s''ñÑ. ]+$')
    CHECK ("last_name" ~ '^[A-Za-z\s''ñÑ. ]+$')
);

-----------------------------------------------------------------------------------------------
-- SESSION FAILED
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "session_failed" CASCADE;
CREATE TABLE "session_failed" (
    "session_failed_id"     INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "user_name"             CHAR(4)        NOT NULL,
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP
);

-----------------------------------------------------------------------------------------------
-- DIRECTORATE
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "directorate" CASCADE;
CREATE TABLE "directorate" (
    "directorate_id"        INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "name"                  VARCHAR(40) UNIQUE  NOT NULL,
    "is_active"             BOOLEAN             NOT NULL    DEFAULT TRUE,
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP

    CHECK ("name" ~ '^[A-Za-znÑ ]+$')
);

-----------------------------------------------------------------------------------------------
-- SECTOR
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "sector" CASCADE;
CREATE TABLE "sector" (
    "sector_id"             INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "name"                  VARCHAR(40) UNIQUE  NOT NULL,
    "is_active"             BOOLEAN             NOT NULL    DEFAULT TRUE,
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP

    CHECK ("name" ~ '^[A-Za-znÑ ]+$')
);

-----------------------------------------------------------------------------------------------
-- DIRECTORATE HAS SECTOR
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "directorate_has_sector" CASCADE;
CREATE TABLE "directorate_has_sector" (
    "destination_id"        INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "directorate_fk"        INTEGER             NOT NULL    REFERENCES "directorate"(directorate_id),
    "sector_fk"             INTEGER             NOT NULL    REFERENCES "sector"(sector_id),
    "name"                  VARCHAR(80) UNIQUE,
    "level"                 CHAR(1),
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    CHECK ("name" ~ '^[A-Za-znÑ -]+$'),
    CHECK ("level" ~ '^[0-9]+$')
);

DROP INDEX IF EXISTS unique_directorate_sector;
CREATE UNIQUE INDEX unique_directorate_sector ON "directorate_has_sector" (
    "directorate_fk",
    "sector_fk"
);

-----------------------------------------------------------------------------------------------
-- POSITION
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "position" CASCADE;
CREATE TABLE "position" (
    "position_id"           INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "name"                  VARCHAR(70)  UNIQUE NOT NULL,
    "is_active"             BOOLEAN             NOT NULL    DEFAULT TRUE,
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP

    CHECK ("name" ~ '^[A-Za-z\s''ñÑ. ]+$')
);

-----------------------------------------------------------------------------------------------
-- EMPLOYEE
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "employee" CASCADE;
CREATE TABLE "employee" (
    "employee_id"           INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "position_fk"           INTEGER             REFERENCES "position"(position_id),
    "destination_fk"        INTEGER             REFERENCES "directorate_has_sector"(destination_id),
    "name"                  VARCHAR(100)        NOT NULL,
    "last_name"             VARCHAR(100)        NOT NULL,
    "is_active"             BOOLEAN             NOT NULL    DEFAULT TRUE,
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP

    CHECK ("name" ~ '^[A-Za-z\s''ñÑ. ]+$')
    CHECK ("last_name" ~ '^[A-Za-z\s''ñÑ. ]+$')
);

-----------------------------------------------------------------------------------------------
-- VISITOR
-----------------------------------------------------------------------------------------------
DROP TABLE IF EXISTS "visitor" CASCADE;
CREATE TABLE "visitor" (
    "visitor_id"            INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "user_fk"               INTEGER             NOT NULL    REFERENCES "user"(user_id),
    "employee_fk"           INTEGER             NOT NULL    REFERENCES "employee"(employee_id),
    "destination_fk"        INTEGER             NOT NULL    REFERENCES "directorate_has_sector"(destination_id),
    "name"                  VARCHAR(100)        NOT NULL,
    "last_name"             VARCHAR(100)        NOT NULL,
    "document_type"         document_options    NOT NULL,
    "document_number"       VARCHAR(20)         NOT NULL,
    "image"                 VARCHAR(50),
    "note"                  TEXT,    
    "entry"                 TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "exit"                  TIMESTAMP,               
    "created_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMP           NOT NULL    DEFAULT CURRENT_TIMESTAMP

    CHECK ("name" ~ '^[A-Za-z\s''ñÑ. ]+$')
    CHECK ("last_name" ~ '^[A-Za-z\s''ñÑ. ]+$')
    CHECK ("document_number" ~ '^[A-Za-znÑ0-9]+$')
);

CREATE OR REPLACE FUNCTION public.user_login(user_name character varying, user_password character varying)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
    was_found INTEGER;
BEGIN 
    SELECT u.user_id INTO was_found
    FROM "user" u 
    WHERE u.profile = user_name
    AND u.password = crypt(user_password, password);
    
    IF was_found IS NULL THEN 
        INSERT INTO session_failed (user_name)
        VALUES(user_name);

        RETURN 0;
    END IF;

    UPDATE "user"
    SET last_login = now() WHERE "profile" = user_name;

    RETURN was_found;
END;
$function$;


-- SELECT user_login('baig', '43721804');

-- DROP EXTENSION IF EXISTS pgcrypto;
CREATE extension pgcrypto; -- biblioteca para encriptar contraseña

CREATE OR REPLACE FUNCTION validate_password()
RETURNS trigger AS 
$$
BEGIN
    -- Validar que la contraseña tenga al menos 8 caracteres
    IF length(NEW.password) < 8 THEN
        RAISE EXCEPTION 'La contraseña debe tener al menos 8 caracteres';
    END IF;

    -- Hashear la contraseña
    NEW.password = crypt(NEW.password, gen_salt('bf'));

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

---------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------

-- USER 
CREATE TRIGGER trg_insert_user_validate_password
BEFORE INSERT ON "user"
FOR EACH ROW
EXECUTE FUNCTION validate_password();

CREATE TRIGGER trg_update_user_validate_password
BEFORE UPDATE ON "user"
FOR EACH ROW
WHEN (NEW.password <> OLD.password)
EXECUTE FUNCTION validate_password();

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

CREATE OR REPLACE FUNCTION is_active_directorate_has_sector()
RETURNS TRIGGER AS $$
DECLARE 
	directorate_name varchar(100);
	sector_name varchar(100);
BEGIN

    SELECT d."name" INTO directorate_name 
    FROM "directorate_has_sector" dhs
    INNER JOIN "directorate" d on d.directorate_id = dhs.directorate_fk
    WHERE dhs.destination_id = NEW.destination_fk 
    AND d.is_active = false;

    SELECT s."name" INTO sector_name 
    FROM "directorate_has_sector" dhs
    INNER JOIN "sector" s on s.sector_id = dhs.sector_fk
    WHERE dhs.destination_id = NEW.destination_fk
    AND s.is_active = false;

    IF directorate_name IS NOT NULL THEN
        RAISE EXCEPTION 'No se puede INSERT, UPDATE o DELETE el registro. La dirección referenciada (%) no está activa.', directorate_name;
    END IF;

    IF sector_name IS NOT NULL THEN
        RAISE EXCEPTION 'No se puede INSERT, UPDATE o DELETE el registro. El sector referenciado (%) no está activo.', directorate_has_sector_name;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------

-- VISITOR
CREATE TRIGGER trg_is_active_directorate_has_sector_for_visitor
BEFORE INSERT OR UPDATE ON "visitor"
FOR EACH ROW
EXECUTE FUNCTION is_active_directorate_has_sector();

CREATE OR REPLACE FUNCTION is_active_directorate()
RETURNS TRIGGER AS $$
DECLARE 
	directorate_name varchar(100);
BEGIN
    SELECT d."name" INTO directorate_name 
    FROM "directorate" d
    WHERE d.directorate_id = NEW.directorate_fk AND d.is_active = false;

    IF directorate_name IS NOT NULL THEN
        RAISE EXCEPTION 'No se puede INSERT, UPDATE o DELETE el registro. La dirección referenciada (%) no está activa.', directorate_name;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION verify_employees_update_is_active_directorate()
RETURNS TRIGGER AS $$
DECLARE 
	cant INTEGER;
BEGIN

    IF NEW.is_active = false THEN
        SELECT COUNT(*) INTO cant
        FROM "employee" e
        INNER JOIN "directorate_has_sector" dhs ON dhs.destination_id = e.destination_fk
        WHERE dhs.directorate_fk = NEW.directorate_id
        AND e.is_active = true;

        IF cant > 0 THEN
            RAISE EXCEPTION 'No se puede desactivar la dirección. Existen empleados activos en la dirección.';
        END IF;

    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------

-- DIRECTORATE HAS SECTOR
CREATE TRIGGER trg_is_active_directorate_for_directorate_has_sector
BEFORE INSERT OR UPDATE ON "directorate_has_sector"
FOR EACH ROW
EXECUTE FUNCTION is_active_directorate();

-- DIRECTORATE
CREATE TRIGGER trg_update_verify_employees_for_directorate
BEFORE UPDATE ON "directorate"
FOR EACH ROW
WHEN (NEW.is_active <> OLD.is_active)
EXECUTE FUNCTION verify_employees_update_is_active_directorate();

CREATE OR REPLACE FUNCTION is_active_employee()
RETURNS TRIGGER AS $$
DECLARE 
	employee_name varchar(100);
BEGIN
    SELECT e."name" INTO employee_name 
    FROM "employee" e
    WHERE e.employee_id = NEW.employee_fk AND e.is_active = false;

    IF employee_name IS NOT NULL THEN
        RAISE EXCEPTION 'No se puede INSERT, UPDATE o DELETE el registro. El empleado/a referenciado (%) no está activo.', employee_name;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------

-- VISITOR
CREATE TRIGGER trg_is_active_employee_for_visitor
BEFORE INSERT OR UPDATE ON "visitor"
FOR EACH ROW
EXECUTE FUNCTION is_active_employee();

CREATE OR REPLACE FUNCTION verify_employees_update_is_active_position()
RETURNS TRIGGER AS $$
DECLARE 
	cant INTEGER;
BEGIN

    IF NEW.is_active = false THEN
        SELECT COUNT(*) INTO cant
        FROM "employee" e
        WHERE e.position_fk = NEW.position_id
        AND e.is_active = true;

        IF cant > 0 THEN
            RAISE EXCEPTION 'No se puede desactivar el cargo. Existen empleados activos con ese cargo.';
        END IF;

    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------

-- POSITION
CREATE TRIGGER trg_update_verify_employees_for_position
BEFORE UPDATE ON "position"
FOR EACH ROW
WHEN (NEW.is_active <> OLD.is_active)
EXECUTE FUNCTION verify_employees_update_is_active_position();

CREATE OR REPLACE FUNCTION is_active_sector()
RETURNS TRIGGER AS $$
DECLARE 
	sector_name varchar(100);
BEGIN
    SELECT s."name" INTO sector_name 
    FROM "sector" s
    WHERE s.sector_id = NEW.sector_fk AND s.is_active = false;

    IF sector_name IS NOT NULL THEN
        RAISE EXCEPTION 'No se puede INSERT, UPDATE o DELETE el registro. El sector referenciado (%) no está activo.', sector_name;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION verify_employees_update_is_active_sector()
RETURNS TRIGGER AS $$
DECLARE 
	cant INTEGER;
BEGIN

    IF NEW.is_active = false THEN
        SELECT COUNT(*) INTO cant
        FROM "employee" e
        INNER JOIN "directorate_has_sector" dhs ON dhs.destination_id = e.destination_fk
        WHERE dhs.sector_fk = NEW.sector_id
        AND e.is_active = true;

        IF cant > 0 THEN
            RAISE EXCEPTION 'No se puede desactivar la dirección. Existen empleados activos en el sector.';
        END IF;

    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------

-- DIRECTORATE HAS SECTOR
CREATE TRIGGER trg_is_active_sector_for_directorate_has_sector
BEFORE INSERT OR UPDATE ON "directorate_has_sector"
FOR EACH ROW
EXECUTE FUNCTION is_active_sector();

-- SECTOR
CREATE TRIGGER trg_update_verify_employees_for_sector
BEFORE UPDATE ON "sector"
FOR EACH ROW
WHEN (NEW.is_active <> OLD.is_active)
EXECUTE FUNCTION verify_employees_update_is_active_sector();

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



