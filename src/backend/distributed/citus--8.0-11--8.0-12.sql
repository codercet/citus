/* citus--8.0-10--8.0-11 */
DO LANGUAGE plpgsql
$$
BEGIN
    -- citus requires ssl form this version onwards. For older installations that didn't
    -- change the citus.node_conninfo setting this will cause the new default value to be
    -- used.
    -- This default value is incompatible with postgres' default setting for ssl and thus
    -- we warn the user they need to either enable ssl, or change citus to not require
    -- ssl.
    -- During a clean installation of citus on postgres we actually intercept the create
    -- extension command to create a certificate and enable ssl. Only if the extension is
    -- installed by a cascade on an other extension we will not have setup ssl, so this
    -- warning will also be shown to the user.
    IF
        TRUE -- hack to easily move around the checks below

		AND current_setting('ssl_ciphers') != 'none' -- test if ssl is compiled into postgres
		AND NOT current_setting('ssl')::boolean -- test if ssl is off
		AND current_setting('citus.node_conninfo') = 'sslmode=require' -- test citus.node_conninfo is set to the default value of sslmode=prefer
	THEN
		-- we have determined that citus wants to use ssl, but ssl is not enabled. we warn
		-- the user and provide them with the options to resolve the issue.
		RAISE WARNING 'citus requires ssl by default but is not configured with ssl enabled'
		      USING HINT = 'either enable ssl on all your nodes or change citus.node_conninfo to not require ssl during connecting';
	END IF;
END;
$$;
