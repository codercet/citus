/*-------------------------------------------------------------------------
 *
 * extension.c
 *    Commands for creating and altering extensions.
 *
 * Copyright (c) 2018, Citus Data, Inc.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "citus_version.h"
#include "distributed/commands.h"
#include "distributed/metadata_cache.h"
#include "distributed/worker_protocol.h"
#include "nodes/parsenodes.h"
#include "postmaster/postmaster.h"
#include "utils/guc.h"

#define DirectFunctionCall0(func) \
	DirectFunctionCall0Coll(func, InvalidOid)
#define ENABLE_SSL_QUERY "ALTER SYSTEM SET ssl TO on;"

/* Local functions forward declarations for helper functions */
static char * ExtractNewExtensionVersion(Node *parsetree);
static Datum DirectFunctionCall0Coll(PGFunction func, Oid collation);

/* use pg's implementation that is not exposed in a header file, fingers crossed */
extern Datum pg_reload_conf(PG_FUNCTION_ARGS);

/*
 * IsCitusExtensionStmt returns whether a given utility is a CREATE or ALTER
 * EXTENSION statement which references the citus extension. This function
 * returns false for all other inputs.
 */
bool
IsCitusExtensionStmt(Node *parsetree)
{
	char *extensionName = "";

	if (IsA(parsetree, CreateExtensionStmt))
	{
		extensionName = ((CreateExtensionStmt *) parsetree)->extname;
	}
	else if (IsA(parsetree, AlterExtensionStmt))
	{
		extensionName = ((AlterExtensionStmt *) parsetree)->extname;
	}

	return (strcmp(extensionName, "citus") == 0);
}


/*
 * ErrorIfUnstableCreateOrAlterExtensionStmt compares CITUS_EXTENSIONVERSION
 * and version given CREATE/ALTER EXTENSION statement will create/update to. If
 * they are not same in major or minor version numbers, this function errors
 * out. It ignores the schema version.
 */
void
ErrorIfUnstableCreateOrAlterExtensionStmt(Node *parsetree)
{
	char *newExtensionVersion = ExtractNewExtensionVersion(parsetree);

	if (newExtensionVersion != NULL)
	{
		/*  explicit version provided in CREATE or ALTER EXTENSION UPDATE; verify */
		if (!MajorVersionsCompatible(newExtensionVersion, CITUS_EXTENSIONVERSION))
		{
			ereport(ERROR, (errmsg("specified version incompatible with loaded "
								   "Citus library"),
							errdetail("Loaded library requires %s, but %s was specified.",
									  CITUS_MAJORVERSION, newExtensionVersion),
							errhint("If a newer library is present, restart the database "
									"and try the command again.")));
		}
	}
	else
	{
		/*
		 * No version was specified, so PostgreSQL will use the default_version
		 * from the citus.control file.
		 */
		CheckAvailableVersion(ERROR);
	}
}


void
ProcessCitusExtensionStmt(Node *parsetree)
{
	if (IsA(parsetree, CreateExtensionStmt))
	{
		/*
		 * during the creation of citus we check if ssl is on, if it is not on we will
		 * turn it on and generate certificates and keys when not existing. This makes
		 * citus secure by default.
		 */

		if (!EnableSSL)
		{
			/* execute the alter system statement to enable ssl on within postgres */
			Node *enableSSLParseTree = ParseTreeNode(ENABLE_SSL_QUERY);
			AlterSystemSetConfigFile((AlterSystemStmt *) enableSSLParseTree);

			/*TODO check if certificates are existing, otherwise create the certificate and its key */

			/* changing the ssl setting requires a reload of the configuration */
			DirectFunctionCall0(pg_reload_conf);
		}
	}
}


/*
 * ExtractNewExtensionVersion returns the new extension version specified by
 * a CREATE or ALTER EXTENSION statement. Other inputs are not permitted. This
 * function returns NULL for statements with no explicit version specified.
 */
static char *
ExtractNewExtensionVersion(Node *parsetree)
{
	char *newVersion = NULL;
	List *optionsList = NIL;
	ListCell *optionsCell = NULL;

	if (IsA(parsetree, CreateExtensionStmt))
	{
		optionsList = ((CreateExtensionStmt *) parsetree)->options;
	}
	else if (IsA(parsetree, AlterExtensionStmt))
	{
		optionsList = ((AlterExtensionStmt *) parsetree)->options;
	}
	else
	{
		/* input must be one of the two above types */
		Assert(false);
	}

	foreach(optionsCell, optionsList)
	{
		DefElem *defElement = (DefElem *) lfirst(optionsCell);
		if (strncmp(defElement->defname, "new_version", NAMEDATALEN) == 0)
		{
			newVersion = strVal(defElement->arg);
			break;
		}
	}

	return newVersion;
}


static Datum
DirectFunctionCall0Coll(PGFunction func, Oid collation)
{
	FunctionCallInfoData fcinfo;
	Datum result;

	InitFunctionCallInfoData(fcinfo, NULL, 0, collation, NULL, NULL);

	result = (*func)(&fcinfo);

	/* Check for null result, since caller is clearly not expecting one */
	if (fcinfo.isnull)
	{
		elog(ERROR, "function %p returned NULL", (void *) func);
	}

	return result;
}
