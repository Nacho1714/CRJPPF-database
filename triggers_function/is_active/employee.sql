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