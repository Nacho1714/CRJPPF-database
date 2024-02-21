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