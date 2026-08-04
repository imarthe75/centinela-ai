from core import db_manager
from psycopg2.extras import RealDictCursor

def check_schema():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    column_name, 
                    data_type, 
                    is_nullable
                FROM 
                    information_schema.columns
                WHERE 
                    table_name = 'remediation_history';
            """)
            columns = cur.fetchall()
            print("Columns in remediation_history:")
            for col in columns:
                print(col)
                
            cur.execute("""
                SELECT
                    conname as constraint_name,
                    contype as constraint_type
                FROM
                    pg_constraint
                WHERE
                    conrelid = 'remediation_history'::regclass;
            """)
            constraints = cur.fetchall()
            print("\nConstraints in remediation_history:")
            for con in constraints:
                print(con)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_schema()
