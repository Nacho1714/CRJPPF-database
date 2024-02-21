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
