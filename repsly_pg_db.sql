CREATE SCHEMA repsly;

CREATE TABLE repsly.raw_json_data (
	id serial4 NOT NULL,
	endpoint_name varchar(50) NOT NULL,
	"data" jsonb NOT NULL,
	created_at timestamp DEFAULT CURRENT_TIMESTAMP NULL,
	updated_at timestamp DEFAULT CURRENT_TIMESTAMP NULL,
	CONSTRAINT raw_json_data_pkey PRIMARY KEY (id)
);


CREATE OR REPLACE FUNCTION repsly.update_timestamp()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;

CREATE TRIGGER update_raw_json_data_timestamp before
update
    on
    repsly.raw_json_data for each row execute function repsly.update_timestamp();
