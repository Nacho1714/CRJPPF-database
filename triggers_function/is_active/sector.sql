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