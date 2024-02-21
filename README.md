# Estructura de la Base de Datos

## Tabla "user"

### Estructura
La tabla "user" tiene la siguiente estructura:

| Columna       | Tipo              | Restricciones                        |
|---------------|-------------------|--------------------------------------|
| `user_id`     | **PRIMARY KEY**   |                                      |
| `name`        | **VARCHAR(100)**  | NOT NULL                             |
| `last_name`   | **VARCHAR(100)**  | NOT NULL                             |
| `profile`     | **CHAR(4)**       | UNIQUE NOT NULL                      |
| `password`    | **VARCHAR(100)**  | NOT NULL                             |
| `last_login`  | **TIMESTAMP**     |                                      |
| `is_active`   | **BOOLEAN**       | NOT NULL DEFAULT TRUE                |
| `created_at`  | **TIMESTAMP**     | NOT NULL DEFAULT CURRENT_TIMESTAMP   |
| `updated_at`  | **TIMESTAMP**     | NOT NULL DEFAULT CURRENT_TIMESTAMP   |

### Descripción
La tabla "user" almacena información de los usuarios del sistema, como nombres, perfiles, contraseñas, logueos y estados de activación. Su función principal es gestionar y mantener registros de los usuarios.

Esta tabla facilita la gestión y autenticación de los usuarios que interactúan con la dashboard. Asi como tambien, permite controlar las sesiones de los usuarios y su estado de activación.

### Restricciones (CHECK)
| Campo        | Descripción                                               |
|--------------|---------------------------------------------------------- |
| `name`       | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)   |
| `last_name`  | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)   |

### Validaciones (TRIGGER)
| Campo               | Disparador                      | Descripción                                   |
|---------------------|---------------------------------|-----------------------------------------------|
| `profile`           | **[I][U][<>][profile]**         | Valida que sea un perfil de 4 letras.         |
| `password`          | **[I][U][<>][password]**        | Valida que el valor >= 8 y luego lo hashea.   |
| `name`              | **[I][U][<>][name][last_name]** | Realiza un "UPPER" y "TRIM" a la cadena.      |
| `created_at`        | **[U]**                         | Valida que el valor no pueda ser modificado.  |
| `updated_at`        | **[U]**                         | Actualiza el valor automaticamente.           |

### Procedimiento Almacenado
`user_login(user.profile, user.password)`: Procedimiento almacenado que permite autenticar a un usuario en el sistema.

***

## Tabla "session_failed"

### Estructura
La tabla "session_failed" tiene la siguiente estructura:

| Columna               | Tipo              | Restricciones                        |
|-----------------------|-------------------|--------------------------------------|
| `session_failed_id`   | **PRIMARY KEY**   |                                      |
| `user_name`           | **VARCHAR(100)**  | NOT NULL                             |
| `created_at`          | **TIMESTAMP**     | NOT NULL DEFAULT CURRENT_TIMESTAMP   |

### Descripción
La tabla "session_failed" almacena los intentos fallidos de inicio de sesión. 

Su función principal es registrar los intentos fallidos de inicio de sesión, proporcionando un registro detallado de los eventos de autenticación en el sistema.

### Validaciones (TRIGGER)
| Campo               | Disparador                | Descripción                                     |
|---------------------|---------------------------|-------------------------------------------------|
| `created_at`        | **[U]**                   | Valida que el valor no pueda ser modificado.    |

***

## Tabla "directorate"

### Estructura
La tabla "directorate" tiene la siguiente estructura:

| Columna           | Tipo              | Restricciones                            |
|----------------   |-------------------|------------------------------------------|
| `directorate_id`  | **PRIMARY KEY**   |                                          |
| `name`            | **VARCHAR(40)**   | NOT NULL                                 |
| `is_active`       | **BOOLEAN**       | NOT NULL DEFAULT TRUE                    |
| `created_at`      | **TIMESTAMP**     | NOT NULL DEFAULT CURRENT_TIMESTAMP       |
| `updated_at`      | **TIMESTAMP**     | NOT NULL DEFAULT CURRENT_TIMESTAMP       |

### Descripción
La tabla "directorate" almacena información sobre las direcciones que componen el organismo. 

Su función principal es gestionar y mantener registros de las direcciones.

### Restricciones (CHECK)
| Campo        | Descripción                                               |
|--------------|---------------------------------------------------------- |
| `name`       | Valida contra la siguiente "regex" (^[A-Za-znÑ ]+$)   |

### Validaciones (TRIGGER)
| Campo               | Disparador                | Descripción                                                                         |
|---------------------|---------------------------|-------------------------------------------------------------------------------------|
| `is_active`         | **[U][<>][is_active]**    | Valida que el registro no pueda ser desactivado, si existen empleados vinculados.   |
| `name`              | **[I][U][<>][name]**      | Realiza un "UPPER" y "TRIM" a la cadena.                                            |
| `created_at`        | **[U]**                   | Valida que el valor no pueda ser modificado.                                        |
| `updated_at`        | **[U]**                   | Actualiza el valor automaticamente.                                                 |

***

## Tabla "sector"

### Estructura
La tabla "sector" tiene la siguiente estructura:

| Columna           | Tipo              | Restricciones                        |
|-------------------|-------------------|--------------------------------------|
| `sector_id`       | **PRIMARY KEY**   |                                      |
| `name`            | **VARCHAR(40)**   | NOT NULL                             |
| `is_active`       | **BOOLEAN**       | NOT NULL DEFAULT TRUE                |
| `created_at`      | **TIMESTAMP**     | NOT NULL DEFAULT CURRENT_TIMESTAMP   |
| `updated_at`      | **TIMESTAMP**     | NOT NULL DEFAULT CURRENT_TIMESTAMP   |

### Descripción
La tabla "sector" almacena información sobre los sectores que componen el organismo y las direcciones. 

Su función principal es gestionar y mantener registros de los sectores.

### Restricciones (CHECK)
| Campo        | Descripción                                               |
|--------------|---------------------------------------------------------- |
| `name`       | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)   |

### Validaciones (TRIGGER)
| Campo               | Disparador                | Descripción                                                                         |
|---------------------|---------------------------|-------------------------------------------------------------------------------------|
| `is_active`         | **[U][<>][is_active]**    | Valida que el registro no pueda ser desactivado, si existen empleados vinculados.   |
| `name`              | **[I][U][<>][name]**      | Realiza un "UPPER" y "TRIM" a la cadena.                                            |
| `created_at`        | **[U]**                   | Valida que el valor no pueda ser modificado.                                        |
| `updated_at`        | **[U]**                   | Actualiza el valor automaticamente.                                                 |

***

## Tabla "directorate_has_sector"

### Estructura
La tabla "directorate_has_sector" tiene la siguiente estructura:

| Columna           | Tipo                | Restricciones                                       |
|-------------------|---------------------|-----------------------------------------------------|
| `destination_id`  | **PRIMARY KEY**     |                                                     |
| `directorate_fk`  | **FOREIGN KEY**     | NOT NULL REFERENCES "directorate"(directorate_id)   |
| `sector_fk`       | **FOREIGN KEY**     | NOT NULL REFERENCES "sector"(sector_id)             |
| `name`            | **VARCHAR(80)**     | UNIQUE                                              |
| `level`           | **CHAR(1)**         |                                                     |
| `created_at`      | **TIMESTAMP**       | NOT NULL DEFAULT CURRENT_TIMESTAMP                  |
| `updated_at`      | **TIMESTAMP**       | NOT NULL DEFAULT CURRENT_TIMESTAMP                  |

| Índice Único                                                            |
|-------------------------------------------------------------------------|
| `UNIQUE INDEX (directorate_fk, sector,fk)`                              |

### Descripción
La tabla pivot "directorate_has_sector" almacena información sobre los sectores pertenecientes a una dirección determinada. 

Su función principal es gestionar y mantener registros de los sectores que componen cada dirección.

### Restricciones (CHECK)
| Campo        | Descripción                                                  |
|--------------|--------------------------------------------------------------|
| `name`       | Valida contra la siguiente "regex" (^[A-Za-znÑ -]+$)         |
| `level`      | Valida contra la siguiente "regex" (^[0-9]+$)                |

### Validaciones (TRIGGER)
| Campo                     | Disparador                                | Descripción                                                                         |
|---------------------------|-------------------------------------------|-------------------------------------------------------------------------------------|
| `directorate.is_active`   | **[I][U]**                                | Valida que la dirección referenciada este activa.                                   |
| `sector.is_active`        | **[I][U]**                                | Valida que el sector referenciado este activo.                                      |
| `name`                    | **[I][U][<>][directorate_fk][sector_fk]** | Construye el nombre automaticamente si no se le pasa ninguna "name" determinado.    |
| `name`                    | **[I][U][<>][name]**                      | Realiza un "UPPER" y "TRIM" a la cadena.                                            |
| `created_at`              | **[U]**                                   | Valida que el valor no pueda ser modificado.                                        |
| `updated_at`              | **[U]**                                   | Actualiza el valor automaticamente.                                                 |

***

## Tabla "position"

### Estructura
La tabla "position" tiene la siguiente estructura  

| Columna           | Tipo                | Restricciones                         |
|-------------------|---------------------|---------------------------------------|
| `position_id`     | **PRIMARY KEY**     |                                       |
| `name`            | **VARCHAR(70)**     | UNIQUE NOT NULL                       |
| `is_active`       | **BOOLEAN**         | NOT NULL DEFAULT TRUE                 |
| `created_at`      | **TIMESTAMP**       | NOT NULL DEFAULT CURRENT_TIMESTAMP    |
| `updated_at`      | **TIMESTAMP**       | NOT NULL DEFAULT CURRENT_TIMESTAMP    |

### Descripción
La tabla "position" gestiona los cargos establecidos en el organismos para cada empleado. 

Su función principal es gestionar y mantener registros de los cargos.

### Restricciones (CHECK)
| Campo        | Descripción                                                  |
|--------------|--------------------------------------------------------------|
| `name`       | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)      |

### Validaciones (TRIGGER)
| Campo                     | Disparador                | Descripción                                                                         |
|---------------------------|---------------------------|-------------------------------------------------------------------------------------|
| `name`                    | **[I][U][<>][name]**      | Realiza un "UPPER" y "TRIM" a la cadena.                                            |
| `is_active`               | **[U][<>][is_active]**    | Valida que el registro no pueda ser desactivado, si existen empleados vinculados.   |
| `created_at`              | **[U]**                   | Valida que el valor no pueda ser modificado.                                        |
| `updated_at`              | **[U]**                   | Actualiza el valor automaticamente.                                                 |

***

## Tabla "employee"

### Estructura
La tabla "employee" tiene la siguiente estructura  

| Columna           | Tipo                | Restricciones                                           |
|-------------------|---------------------|---------------------------------------------------------|
| `employee_id`     | **PRIMARY KEY**     |                                                         |
| `position_fk`     | **FOREIGN KEY**     | REFERENCES "position"(position_id)                      |
| `destination_fk`  | **FOREIGN KEY**     | REFERENCES "directorate_has_sector"(destination_id)     |
| `name`            | **VARCHAR(100)**    | NOT NULL                                                |
| `last_name`       | **VARCHAR(100)**    | NOT NULL                                                |
| `is_active`       | **BOOLEAN**         | NOT NULL DEFAULT TRUE                                   |
| `created_at`      | **TIMESTAMP**       | NOT NULL DEFAULT CURRENT_TIMESTAMP                      |
| `updated_at`      | **TIMESTAMP**       | NOT NULL DEFAULT CURRENT_TIMESTAMP                      |

### Descripción
La tabla "employee" gestiona los empleados del organismo, su cargo y ubicación. 

Su función principal es gestionar y mantener registros de los empleados.

### Restricciones (CHECK)
| Campo        | Descripción                                                  |
|--------------|--------------------------------------------------------------|
| `name`       | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)      |
| `last_name`  | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)      |

### Validaciones (TRIGGER)
| Campo                     | Disparador                        | Descripción                                                 |
|---------------------------|-----------------------------------|-------------------------------------------------------------|
| `name`                    | **[I][U][<>][name][last_name]**   | Realiza un "UPPER" y "TRIM" a la cadena.                    |
| `created_at`              | **[U]**                           | Valida que el valor no pueda ser modificado.                |
| `updated_at`              | **[U]**                           | Actualiza el valor automaticamente.                         |

***

## Tabla "visitor"

### Estructura
La tabla "visitor" tiene la siguiente estructura:

| Columna           | Tipo                  | Restricciones                                                     |
|-------------------|-----------------------|-------------------------------------------------------------------|
| `visitor_id`      | **PRIMARY KEY**       |                                                                   |
| `user_fk`         | **FOREIGN KEY**       | NOT NULL REFERENCES "user"(user_id)                               |
| `employee_fk`     | **FOREIGN KEY**       | NOT NULL REFERENCES "employee"(employee_id)                       |
| `destination_fk`  | **FOREIGN KEY**       | NOT NULL REFERENCES "directorate_has_sector"(destination_id)      |
| `name`            | **VARCHAR(100)**      | NOT NULL                                                          |
| `last_name`       | **VARCHAR(100)**      | NOT NULL                                                          |
| `document_type`   | **document_options**  | NOT NULL                                                          |
| `document_number` | **VARCHAR(20)**       | NOT NULL                                                          |
| `image`           | **VARCHAR(50)**       |                                                                   |
| `note`            | **TEXT**              |                                                                   |
| `entry`           | **TIMESTAMP**         | NOT NULL DEFAULT CURRENT_TIMESTAMP                                |
| `exit`            | **TIMESTAMP**         |                                                                   |
| `created_at`      | **TIMESTAMP**         | NOT NULL DEFAULT CURRENT_TIMESTAMP                                |
| `updated_at`      | **TIMESTAMP**         | NOT NULL DEFAULT CURRENT_TIMESTAMP                                |

### Descripción
La tabla "visitor" registra los visitantes que ingresan al organismo. 

Se asocia a un empleado y una ubicación específica, y almacena información detallada sobre el visitante, como nombre, apellido, tipo y número de documento, fecha de entrada y salida.

### Restricciones (CHECK)
| Campo              | Descripción                                                  |
|--------------------|--------------------------------------------------------------|
| `name`             | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)      |
| `last_name`        | Valida contra la siguiente "regex" ([A-Za-z\s''ñÑ. ]+$)      |
| `document_number`  | Valida contra la siguiente "regex" (^[A-Za-znÑ0-9]+$)        |

### Validaciones (TRIGGER)
| Campo                     | Disparador                        | Descripción                                                 |
|---------------------------|-----------------------------------|-------------------------------------------------------------|
| `directorate.is_active`   | **[I][U]**                        | Valida que la dirección referenciada este activa.           |
| `sector.is_active`        | **[I][U]**                        | Valida que el sector referenciado este activo.              |
| `employee.is_active`      | **[I][U]**                        | Valida que el empleado referenciado este activo.            |
| `user.is_active`          | **[I][U]**                        | Valida que el usuario referenciado este activo.             |
| `name`                    | **[I][U][<>][name][last_name]**   | Realiza un "UPPER" y "TRIM" a la cadena.                    |
| `created_at`              | **[U]**                           | Valida que el valor no pueda ser modificado.                |
| `updated_at`              | **[U]**                           | Actualiza el valor automaticamente.                         |

***

## Tabla "ENUM"

### document_options
* `DNI`
* `LE`
* `LC`
* `PAS`