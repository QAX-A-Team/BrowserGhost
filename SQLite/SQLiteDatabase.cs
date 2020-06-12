//  $Header$
using System;
using System.Data;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Security.Principal;
using System.IO;
using System.Reflection;

namespace CS_SQLite3
{

    using sqlite = CSSQLite.sqlite3;
    using Vdbe = CSSQLite.Vdbe;
  /// <summary>
  /// C#-SQLite wrapper with functions for opening, closing and executing queries.
  /// </summary>
    public class SQLiteDatabase
    {
        // pointer to database
        private sqlite db;

        /// <summary>
        /// Creates new instance of SQLiteBase class with no database attached.
        /// </summary>
        public SQLiteDatabase()
        {
            db = null;
        }
        /// <summary>
        /// Creates new instance of SQLiteDatabase class and opens database with given name.
        /// </summary>
        /// <param name="DatabaseName">Name (and path) to SQLite database file</param>
        public SQLiteDatabase( String DatabaseName )
        {
            OpenDatabase( DatabaseName );
        }

        /// <summary>
        /// Opens database. 
        /// </summary>
        /// <param name="DatabaseName">Name of database file</param>
        public void OpenDatabase( String DatabaseName )
        {
            // opens database 
            if ( CSSQLite.sqlite3_open( DatabaseName, ref db ) != CSSQLite.SQLITE_OK )
            {
            // if there is some error, database pointer is set to 0 and exception is throws
            db = null;
            throw new Exception( "Error with opening database " + DatabaseName + "!" );
            }
        }

        /// <summary>
        /// Closes opened database.
        /// </summary>
        public void CloseDatabase()
        {
            // closes the database if there is one opened
            if ( db != null )
            {
            CSSQLite.sqlite3_close( db );
            }
        }

        /// <summary>
        /// Returns connection
        /// </summary>
        public sqlite Connection()
        {
            return db;
        }

        /// <summary>
        /// Returns the list of tables in opened database.
        /// </summary>
        /// <returns></returns>
        public ArrayList GetTables()
        {
            // executes query that select names of all tables in master table of the database
            String query = "SELECT name FROM sqlite_master " +
                                        "WHERE type = 'table'" +
                                        "ORDER BY 1";
            DataTable table = ExecuteQuery( query );

            // Return all table names in the ArrayList
            ArrayList list = new ArrayList();
            foreach ( DataRow row in table.Rows )
            {
            list.Add( row.ItemArray[0].ToString() );
            }
            return list;
        }

        /// <summary>
        /// Executes query that does not return anything (e.g. UPDATE, INSERT, DELETE).
        /// </summary>
        /// <param name="query"></param>
        public void ExecuteNonQuery( String query )
        {
            // calles SQLite function that executes non-query
            CSSQLite.sqlite3_exec( db, query, 0, 0, 0 );
            // if there is error, excetion is thrown
            if ( db.errCode != CSSQLite.SQLITE_OK )
            throw new Exception( "Error with executing non-query: \"" + query + "\"!\n" + CSSQLite.sqlite3_errmsg( db ) );
        }

        /// <summary>
        /// Executes query that does return something (e.g. SELECT).
        /// </summary>
        /// <param name="query"></param>
        /// <returns></returns>
        public DataTable ExecuteQuery( String query )
        {
            // compiled query
            SQLiteVdbe statement = new SQLiteVdbe(this, query);

            // table for result of query
            DataTable table = new DataTable();

            // create new instance of DataTable with name "resultTable"
            table = new DataTable( "resultTable" );

            // reads rows
            do { } while ( ReadNextRow( statement.VirtualMachine(), table ) == CSSQLite.SQLITE_ROW );
            // finalize executing this query
            statement.Close();
            // returns table
            return table;
        }

        // private function for reading rows and creating table and columns
        private int ReadNextRow( Vdbe vm, DataTable table )
        {
            int columnCount = table.Columns.Count;
            if ( columnCount == 0 )
            {
            if ( ( columnCount = ReadColumnNames( vm, table ) ) == 0 ) return CSSQLite.SQLITE_ERROR;
            }

            int resultType;
            if ( ( resultType = CSSQLite.sqlite3_step( vm) ) == CSSQLite.SQLITE_ROW )
            {
            object[] columnValues = new object[columnCount];

            for ( int i = 0 ; i < columnCount ; i++ )
            {
                int columnType = CSSQLite.sqlite3_column_type( vm, i );
                switch ( columnType )
                {
                case CSSQLite.SQLITE_INTEGER:
                    {
                    columnValues[i] = CSSQLite.sqlite3_column_int( vm, i );
                    break;
                    }
                case CSSQLite.SQLITE_FLOAT:
                    {
                    columnValues[i] = CSSQLite.sqlite3_column_double( vm, i );
                    break;
                    }
                case CSSQLite.SQLITE_TEXT:
                    {
                    columnValues[i] = CSSQLite.sqlite3_column_text( vm, i );
                    break;
                    }
                case CSSQLite.SQLITE_BLOB:
                            {
                                // Something goes wrong between adding this as a column value and converting to a row value.
                                byte[] encBlob = CSSQLite.sqlite3_column_blob(vm, i);
                                string base64 = Convert.ToBase64String(encBlob);
                                //byte[] decPass = ProtectedData.Unprotect(encBlob, null, DataProtectionScope.CurrentUser);
                                //string password = Encoding.ASCII.GetString(decPass);
                                //columnValues[i] = password;
                                columnValues[i] = base64;
                                
                    break;
                    }
                default:
                    {
                    columnValues[i] = "";
                    break;
                    }
                }
            }
            table.Rows.Add( columnValues );
            }
            return resultType;
        }
        // private function for creating Column Names
        // Return number of colums read
        private int ReadColumnNames( Vdbe vm, DataTable table )
        {

            String columnName = "";
            int columnType = 0;
            // returns number of columns returned by statement
            int columnCount = CSSQLite.sqlite3_column_count( vm );
            object[] columnValues = new object[columnCount];

            try
            {
            // reads columns one by one
            for ( int i = 0 ; i < columnCount ; i++ )
            {
                columnName = CSSQLite.sqlite3_column_name( vm, i );
                columnType = CSSQLite.sqlite3_column_type( vm, i );
                switch ( columnType )
                {
                case CSSQLite.SQLITE_INTEGER:
                    {
                    // adds new integer column to table
                    table.Columns.Add( columnName, Type.GetType( "System.Int64" ) );
                    break;
                    }
                case CSSQLite.SQLITE_FLOAT:
                    {
                    table.Columns.Add( columnName, Type.GetType( "System.Double" ) );
                    break;
                    }
                case CSSQLite.SQLITE_TEXT:
                    {
                    table.Columns.Add( columnName, typeof(string) );
                    break;
                    }
                case CSSQLite.SQLITE_BLOB:
                    {
                    table.Columns.Add( columnName, typeof(byte[]) );
                    break;
                    }
                default:
                    {
                    table.Columns.Add( columnName, Type.GetType( "System.String" ) );
                    break;
                    }
                }
            }
            }
            catch
            {
            return 0;
            }
            return table.Columns.Count;
        }

    }

}

