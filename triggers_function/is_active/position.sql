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