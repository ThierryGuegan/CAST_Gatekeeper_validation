"""Run: python3 test_sql_checkers.py   (no server needed)"""
import sys
import sql_checkers as sq

TP, FP, RV = sq.TP, sq.FP, sq.RV
CASES = [
    # joins
    ("1101000", "SELECT a.x FROM a, b WHERE a.y = 1;", 1, TP),
    ("1101000", "SELECT a.x FROM a, b WHERE a.id = b.id;", 1, FP),
    ("1101000", "SELECT a.x FROM a JOIN b;", 1, TP),
    ("1101000", "SELECT a.x FROM a JOIN b ON a.id = b.id;", 1, FP),
    ("1101000", "SELECT a.x FROM a CROSS JOIN b;", 1, TP),
    ("1101010", "SELECT * FROM a NATURAL JOIN b;", 1, TP),
    ("1101010", "SELECT * FROM a JOIN b ON a.i = b.i;", 1, FP),
    ("1101014", "SELECT a.x FROM a, b WHERE a.id = b.id;", 1, TP),
    ("1101014", "SELECT a.x FROM a JOIN b ON a.id = b.id;", 1, FP),
    ("1101014", "SELECT a.x FROM a, b WHERE a.id = b.id(+);", 1, TP),
    ("1101058", "SELECT 1 FROM a, b JOIN c ON b.i = c.i WHERE a.i = b.i;", 1, TP),
    ("1101058", "SELECT 1 FROM a JOIN c ON a.i = c.i;", 1, FP),
    ("1101072", "SELECT x FROM a JOIN b ON a.i = b.i;", 1, TP),
    ("1101072", "SELECT t.x FROM a t JOIN b u ON t.i = u.i;", 1, FP),
    ("1101074", "SELECT t1.x FROM a t1;", 1, TP),
    ("1101074", "SELECT t.x FROM a t;", 1, FP),
    # select shape
    ("1101114", "SELECT * FROM t;", 1, TP),
    ("1101114", "SELECT a, b FROM t;", 1, FP),
    ("1101114", "SELECT COUNT(*) FROM t;", 1, FP),
    ("1101114", "SELECT 1 FROM x WHERE EXISTS (SELECT * FROM y WHERE y.i = x.i);", 1, FP),
    ("1101034", "SELECT DISTINCT a FROM t;", 1, TP),
    ("1101034", "SELECT COUNT(DISTINCT a) FROM t;", 1, FP),
    ("1101018", "SELECT a, COUNT(*) FROM t GROUP BY a;", 1, TP),
    ("1101018", "-- GROUP BY a\nSELECT a FROM t;", 1, FP),
    ("1101012", "SELECT a, b FROM t ORDER BY 1, 2;", 1, TP),
    ("1101012", "SELECT a, b FROM t ORDER BY a, b;", 1, FP),
    ("1101026", "INSERT INTO t VALUES (1, 2);", 1, TP),
    ("1101026", "INSERT INTO t (a, b) VALUES (1, 2);", 1, FP),
    ("1101026", "INSERT INTO t SELECT a, b FROM u;", 1, TP),
    ("1101028", "SELECT a FROM t WHERE a NOT IN (SELECT a FROM u);", 1, TP),
    ("1101028", "SELECT a FROM t WHERE a IN (SELECT a FROM u);", 1, FP),
    ("1101032", "SELECT a FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.x = 5);", 1, TP),
    ("1101032", "SELECT a FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.x = t.x);", 1, FP),
    ("1101036", "SELECT a FROM t WHERE a != 1;", 1, TP),
    ("1101036", "SELECT a FROM t WHERE a <> 1;", 1, FP),
    ("1101038", "SELECT a FROM t WHERE a = 1 OR a = 2;", 1, TP),
    ("1101038", "SELECT a FROM t WHERE a = 1 OR b = 2;", 1, FP),
    ("1101070", "SELECT a FROM t WHERE a = NULL;", 1, TP),
    ("1101070", "SELECT a FROM t WHERE a IS NULL;", 1, FP),
    ("1101060", "SELECT a FROM t WHERE n LIKE '%abc';", 1, TP),
    ("1101060", "SELECT a FROM t WHERE n LIKE 'abc%';", 1, FP),
    ("1101102", "SELECT a FROM t WHERE n LIKE 'abc';", 1, TP),
    ("1101102", "SELECT a FROM t WHERE n LIKE 'abc%';", 1, FP),
    ("1101008", "SELECT a FROM t WHERE UPPER(n) = 'X';", 1, TP),
    ("1101008", "SELECT a FROM t WHERE n = 'X';", 1, RV),
    ("1101020", 'SELECT "My Col" FROM t;', 1, TP),
    ("1101020", "SELECT a FROM t;", 1, FP),
    # dynamic SQL
    ("1101024", "EXECUTE IMMEDIATE 'DROP TABLE x';", 1, TP),
    ("1101024", "-- EXECUTE IMMEDIATE 'x';\nSELECT 1 FROM t;", 1, FP),
    ("1101096", "EXECUTE IMMEDIATE 'SELECT * FROM t WHERE a = ' || v_a;", 1, TP),
    ("1101096", "EXECUTE IMMEDIATE 'SELECT * FROM t WHERE a = :1' USING v_a;", 1, FP),
    ("1101096", "EXECUTE IMMEDIATE v_sql;", 1, RV),
    # exceptions
    ("1101054", "EXCEPTION\n  WHEN OTHERS THEN NULL;\nEND;", 2, TP),
    ("1101054", "EXCEPTION\n  WHEN OTHERS THEN\n    log_error(SQLERRM);\nEND;", 2, FP),
    ("1101052", "BEGIN\n  x := 1;\nEXCEPTION\n  WHEN NO_DATA_FOUND THEN\n    NULL;\nEND;", 3, TP),
    ("1101052", "BEGIN\n  x := 1;\nEXCEPTION\n  WHEN NO_DATA_FOUND THEN\n    NULL;\n  WHEN OTHERS THEN\n    RAISE;\nEND;", 3, FP),
    ("1101040", "BEGIN TRY\n  SELECT 1;\nEND TRY\nBEGIN CATCH\nEND CATCH", 4, TP),
    ("1101040", "BEGIN TRY\n  SELECT 1;\nEND TRY\nBEGIN CATCH\n  ROLLBACK;\nEND CATCH", 4, FP),
    # loops
    ("1101116", "FOR r IN 1..10 LOOP\n  SELECT a INTO v FROM t WHERE i = r;\nEND LOOP;", 2, TP),
    ("1101116", "SELECT a INTO v FROM t WHERE i = 1;", 1, RV),
    ("1101116", "WHILE @i < 10\nBEGIN\n  SELECT @a = a FROM t WHERE i = @i;\n  SET @i = @i + 1;\nEND", 3, TP),
    ("1101084", "LOOP\n  OPEN c1;\nEND LOOP;", 2, TP),
    # tables
    ("1101022", "CREATE TABLE t (a INT PRIMARY KEY);", 1, FP),
    ("1101022", "CREATE TABLE t (a INT);", 1, TP),
    ("1101022", "CREATE TABLE t (a INT);\nALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (a);", 1, FP),
    ("1101106", "CREATE TABLE t (a INT);\nCREATE UNIQUE INDEX i ON t (a);", 1, FP),
    ("1101106", "CREATE TABLE t (a INT);", 1, TP),
    ("1101090", "CREATE TABLE t (a INT);", 1, TP),
    ("1101090", "CREATE TABLE t (a INT);\nCREATE CLUSTERED INDEX i ON t (a);", 1, FP),
    ("1101078", "CREATE PUBLIC SYNONYM s FOR u.t;", 1, TP),
    ("1101078", "CREATE SYNONYM s FOR u.t;", 1, FP),
    ("1101086", "CREATE TABLE t (a VARCHAR(10));", 1, TP),
    ("1101086", "CREATE TABLE t (a VARCHAR2(10));", 1, FP),
    ("1101088", "CREATE TABLE t (a LONG);", 1, TP),
    ("1101062", "x := 1; y := 2;", 1, TP),
    ("1101062", "x := 1;", 1, FP),
    # COBOL
    ("1101108", "           EXEC SQL DECLARE C1 CURSOR FOR SELECT A FROM T END-EXEC.", 1, TP),
    ("1101108", "           EXEC SQL DECLARE C1 CURSOR FOR SELECT A FROM T FOR READ ONLY END-EXEC.", 1, FP),
    ("1101112", "           EXEC SQL LOCK TABLE T IN SHARE MODE END-EXEC.", 1, TP),
]


def main():
    bad = 0
    for rid, src, line, want in CASES:
        ctx = sq.SqlCtx(src.splitlines())
        got, why, ev = sq.RULES[rid][1](ctx, line)
        if got != want:
            bad += 1
            print(f"FAIL {rid} line {line}: expected {want}, got {got} - {why}\n     src: {src!r}")
    print(f"{len(CASES) - bad}/{len(CASES)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
