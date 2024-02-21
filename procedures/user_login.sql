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