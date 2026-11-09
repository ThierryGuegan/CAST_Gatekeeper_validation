"""Run: python3 test_abap_checkers.py   (no server needed)"""
import sys
import abap_checkers as ac

TP, FP, RV = ac.TP, ac.FP, ac.RV
# (rule, abap source, reported line, expected verdict)
CASES = [
    # --- ENDSELECT family
    ("7544", "SELECT * FROM mara INTO ls WHERE matnr = p.\n  WRITE ls-matnr.\nENDSELECT.", 1, TP),
    ("7544", "SELECT SINGLE * FROM mara INTO ls WHERE matnr = p.", 1, FP),
    ("7544", "SELECT * FROM mara INTO TABLE lt WHERE matnr = p.", 1, FP),
    ("7544", "SELECT COUNT(*) FROM mara INTO lv.", 1, FP),
    ("7544", "SELECT * FROM mara INTO TABLE @DATA(t) PACKAGE SIZE 10.\n  WRITE 1.\nENDSELECT.", 1, TP),
    ("8126", "SELECT * FROM mara INTO ls.\nENDSELECT.", 1, TP),
    ("8126", "SELECT * FROM mara INTO ls.\n  \" only a comment\nENDSELECT.", 1, TP),
    ("8126", "SELECT * FROM mara INTO ls.\n  WRITE ls.\nENDSELECT.", 1, FP),
    ("8132", "SELECT * FROM mara INTO ls.\n  CHECK ls-x = 1.\nENDSELECT.", 1, TP),
    ("8132", "SELECT * FROM mara INTO ls.\n  CHECK ls-x = 1.\nENDSELECT.", 2, TP),   # reported on the CHECK line
    ("8132", "SELECT * FROM mara INTO ls.\n  LOOP AT lt INTO l.\n    EXIT.\n  ENDLOOP.\nENDSELECT.", 1, FP),
    ("8132", "SELECT * FROM mara INTO ls.\n  LOOP AT lt INTO l.\n    RETURN.\n  ENDLOOP.\nENDSELECT.", 1, TP),
    ("8132", "SELECT * FROM mara INTO ls.\n  WRITE 'CHECK. x'.\nENDSELECT.", 1, FP),
    ("7532", "SELECT * FROM a INTO x.\n  SELECT * FROM b INTO y.\n    WRITE y.\n  ENDSELECT.\nENDSELECT.", 1, TP),
    ("7532", "SELECT * FROM a INTO x.\n  SELECT * FROM b INTO y.\n    WRITE y.\n  ENDSELECT.\nENDSELECT.", 2, TP),
    ("7532", "SELECT * FROM a INTO x.\n  WRITE x.\nENDSELECT.", 1, FP),
    ("7880", "LOOP AT a INTO x.\n  LOOP AT b INTO y.\n    WRITE y.\n  ENDLOOP.\nENDLOOP.", 1, TP),
    ("7880", "LOOP AT a INTO x.\n  WRITE x.\nENDLOOP.\nLOOP AT b INTO y.\nENDLOOP.", 1, FP),
    # --- SY-SUBRC
    ("7520", "READ TABLE lt INTO ls INDEX 1.\nWRITE ls.", 1, TP),
    ("7520", "READ TABLE lt INTO ls INDEX 1.\nIF sy-subrc = 0.\n  WRITE ls.\nENDIF.", 1, FP),
    ("7520", "SELECT SINGLE * FROM t INTO ls.\nREAD TABLE lt INTO l2 INDEX 1.\nIF sy-subrc = 0.\nENDIF.", 1, TP),
    ("7520", "READ TABLE lt ASSIGNING <fs> INDEX 1.\nIF <fs> IS ASSIGNED.\nENDIF.", 1, FP),
    ("8012", "OPEN DATASET p FOR INPUT IN TEXT MODE ENCODING DEFAULT.\nIF sy-subrc <> 0.\n  RETURN.\nENDIF.", 1, FP),
    ("8012", "OPEN DATASET p FOR INPUT IN TEXT MODE ENCODING DEFAULT.\nREAD DATASET p INTO s.", 1, TP),
    ("8014", "AUTHORITY-CHECK OBJECT 'S_X' ID 'ACTVT' FIELD '03'.\nIF sy-subrc <> 0.\nENDIF.", 1, FP),
    ("8014", "AUTHORITY-CHECK OBJECT 'S_X' ID 'ACTVT' FIELD '03'.\nWRITE 1.", 1, TP),
    # --- READ TABLE / LOOP / SQL
    ("7534", "READ TABLE lt INTO ls WITH KEY a = 1 BINARY SEARCH.", 1, FP),
    ("7534", "READ TABLE lt INTO ls WITH KEY a = 1.", 1, TP),
    ("7534", "DATA lt TYPE SORTED TABLE OF t WITH UNIQUE KEY a.\nREAD TABLE lt INTO ls WITH KEY a = 1.", 2, FP),
    ("7534", "READ TABLE lt INTO ls INDEX 3.", 1, FP),
    ("7536", "LOOP AT lt INTO ls WHERE a = 1.\n  AT NEW b.\n  ENDAT.\nENDLOOP.", 1, TP),
    ("7536", "LOOP AT lt INTO ls.\n  AT NEW b.\n  ENDAT.\nENDLOOP.", 1, FP),
    ("7894", "LOOP AT lt INTO ls.\nENDLOOP.", 1, TP),
    ("7894", "LOOP AT lt ASSIGNING <fs>.\nENDLOOP.", 1, FP),
    ("7542", "IF lt_k IS NOT INITIAL.\n  SELECT * FROM t INTO TABLE lt FOR ALL ENTRIES IN lt_k WHERE a = lt_k-a.\nENDIF.", 2, FP),
    ("7542", "SELECT * FROM t INTO TABLE lt FOR ALL ENTRIES IN lt_k WHERE a = lt_k-a.", 1, TP),
    ("7542", "SELECT * FROM t INTO TABLE lt WHERE a = 1.", 1, FP),
    ("7878", "SELECT * FROM t INTO TABLE lt.", 1, TP),
    ("7878", "SELECT * FROM t INTO TABLE lt WHERE a = 1.", 1, FP),
    ("7530", "SELECT * FROM t INTO TABLE lt WHERE a = 1.", 1, TP),
    ("7530", "SELECT SINGLE * FROM t INTO ls WHERE a = 1.", 1, TP),
    ("7530", "SELECT a b FROM t INTO TABLE lt WHERE a = 1.", 1, FP),
    ("8134", "SELECT a FROM t INTO TABLE lt WHERE b = 1.\nWRITE 1.", 1, TP),
    ("8134", "SELECT a FROM t INTO TABLE lt WHERE b = 1.\nSORT lt BY a.", 1, FP),
    ("8134", "SELECT a FROM t INTO TABLE lt WHERE b = 1 ORDER BY a.", 1, FP),
    ("7822", "SELECT a FROM t1 JOIN t2 ON t1~a = t2~a JOIN t3 ON t2~b = t3~b JOIN t4 ON t3~c = t4~c JOIN t5 ON t4~d = t5~d INTO TABLE lt.", 1, TP),
    ("7822", "SELECT a FROM t1 JOIN t2 ON t1~a = t2~a INTO TABLE lt.", 1, FP),
    ("7820", "SELECT a FROM t1 JOIN t2 INTO TABLE lt.", 1, TP),
    ("7820", "SELECT a FROM t1 JOIN t2 ON t1~a = t2~a INTO TABLE lt.", 1, FP),
    ("7868", "LOOP AT lt INTO ls.\n  SELECT SINGLE * FROM t INTO l2 WHERE a = ls-a.\nENDLOOP.", 2, TP),
    ("7868", "SELECT SINGLE * FROM t INTO l2 WHERE a = 1.", 1, RV),
    ("7868", "WRITE 1.", 1, FP),
    # --- blocks
    ("7512", "FORM f.\nENDFORM.", 1, TP),
    ("7512", "FORM f.\n  \" nothing\nENDFORM.", 1, TP),
    ("7512", "FORM f.\n  WRITE 1.\nENDFORM.", 1, FP),
    ("7516", "REPORT z.", 1, TP),
    ("7516", "REPORT z.\nWRITE 1.", 1, FP),
    ("8106", "IF a = 1.\nENDIF.", 1, TP),
    ("8106", "IF a = 1.\n  WRITE 1.\nENDIF.", 1, FP),
    ("8106", "IF a = 1.\nELSE.\n  WRITE 1.\nENDIF.", 1, RV),
    ("7518", "CASE a.\n  WHEN 1.\n    WRITE 1.\nENDCASE.", 1, TP),
    ("7518", "CASE a.\n  WHEN 1.\n    WRITE 1.\n  WHEN OTHERS.\nENDCASE.", 1, FP),
    ("7518", "CASE a.\n  WHEN 1.\n    CASE b.\n      WHEN OTHERS.\n    ENDCASE.\nENDCASE.", 1, TP),
    ("7518", "v = COND #( WHEN a = 1 THEN 2 ).", 1, TP),
    ("7518", "v = COND #( WHEN a = 1 THEN 2 ELSE 3 ).", 1, FP),
    ("1104018", "TRY.\n  foo( ).\nCATCH cx_a.\nENDTRY.", 3, TP),
    ("1104018", "TRY.\n  foo( ).\nCATCH cx_a.\n  log( ).\nENDTRY.", 3, FP),
    ("7858", "METHODS m IMPORTING VALUE(iv) TYPE i.", 1, TP),
    ("7858", "METHODS m IMPORTING iv TYPE i RETURNING VALUE(rv) TYPE i.", 1, FP),
    ("7672", "EXIT.", 1, TP),
    ("7672", "LOOP AT lt INTO l.\n  EXIT.\nENDLOOP.", 2, FP),
    ("7906", "IF sy-uname = 'JOHN'.\nENDIF.", 1, TP),
    ("7906", "IF sy-uname = lv_user.\nENDIF.", 1, RV),
    ("7906", "IF sy-datum = lv_d.\nENDIF.", 1, FP),
    ("8430", "lo = cl_abap_random=>create( seed = 42 ).", 1, TP),
    ("8430", "lo = cl_abap_random=>create( seed = cl_abap_random=>seed( ) ).", 1, FP),
    ("8430", "lo = cl_abap_random=>create( ).", 1, TP),
    # --- authorization
    ("8428", "AUTHORITY-CHECK OBJECT 'S_TCODE' ID 'TCD' FIELD 'X'.\nCALL TRANSACTION 'X'.", 2, FP),
    ("8428", "CALL TRANSACTION 'X'.", 1, TP),
    ("8428", "CALL TRANSACTION 'X' WITH AUTHORITY-CHECK.", 1, FP),
    ("8576", "FORM f.\n  OPEN DATASET p FOR INPUT IN TEXT MODE ENCODING DEFAULT.\nENDFORM.", 2, TP),
    ("8576", "FORM f.\n  AUTHORITY-CHECK OBJECT 'S_DATASET' ID 'ACTVT' FIELD '06'.\n  OPEN DATASET p FOR INPUT IN TEXT MODE ENCODING DEFAULT.\nENDFORM.", 3, FP),
    ("8582", "CALL FUNCTION lv_fm.", 1, TP),
    ("8582", "CALL FUNCTION 'Z_FM'.", 1, FP),
    ("8578", "MODIFY SCREEN.", 1, FP),
    ("8578", "MODIFY ztab FROM ls.", 1, RV),
    ("8422", "FORM f ON COMMIT.\n  COMMIT WORK.\nENDFORM.", 2, TP),
    # --- error handling
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1.", 1, TP),
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.", 1, FP),
    ("8120", "TRY.\n  CALL FUNCTION 'Z' EXPORTING a = 1.\nCATCH cx_a.\nENDTRY.", 2, FP),
    ("8120", "TRY.\nCATCH cx_a.\n  CALL FUNCTION 'Z' EXPORTING a = 1.\nENDTRY.", 3, TP),
    ("8122", "CALL METHOD o->m.", 1, TP),
    # --- keyword rules
    ("7524", "BREAK-POINT.", 1, TP),
    ("7524", "BREAK jdoe.", 1, TP),
    ("7524", "* BREAK-POINT.\nWRITE 1.", 1, FP),
    ("7528", "ON CHANGE OF a.\nENDON.", 1, TP),
    ("7592", "SELECT a FROM t INTO TABLE lt ORDER BY a.", 1, TP),
    ("7592", "SELECT a FROM t INTO TABLE lt.", 1, FP),
    ("7594", "SELECT DISTINCT a FROM t INTO TABLE lt.", 1, TP),
    ("7870", "SELECT a FROM t INTO TABLE lt WHERE b NOT LIKE 'X%'.", 1, TP),
    ("7872", "SELECT a FROM t INTO TABLE lt WHERE b IS NULL.", 1, TP),
    ("7874", "SELECT a FROM (lv_tab) INTO TABLE lt WHERE (lv_where).", 1, TP),
    ("7874", "SELECT a FROM t INTO TABLE lt WHERE b IN ('A','B') AND c = COUNT( * ).", 1, FP),
    ("7876", "SELECT SINGLE a FROM t INTO l FOR UPDATE.", 1, TP),
    ("7882", "EXEC SQL.\n  select 1 from dual\nENDEXEC.", 1, TP),
    ("7886", "SYSTEM-CALL CREATE CLASS-OBJECT.", 1, TP),
    ("7806", "SELECT a FROM t INTO TABLE lt GROUP BY a.", 1, TP),
    ("7808", "SELECT a FROM t INTO TABLE lt WHERE b IN ( SELECT b FROM u ).", 1, TP),
    ("8116", "CALL 'C_FOO' ID 'X' FIELD y.", 1, TP),
    ("8118", "CALL FUNCTION 'RFC_ABAP_INSTALL_AND_RUN'.", 1, TP),
    ("8130", "SELECT a FROM t INTO TABLE lt %_HINTS ORACLE 'FOO'.", 1, TP),
    ("8412", "TRY.\nCATCH cx_root INTO lx.\nENDTRY.", 2, TP),
    ("8412", "TRY.\nCATCH cx_root_foo INTO lx.\nENDTRY.", 2, FP),
    ("8426", "CALL 'C_DB_EXECUTE' ID 'STATLEN' FIELD l.", 1, TP),
    ("8432", "SELECT * FROM t CLIENT SPECIFIED INTO TABLE lt WHERE mandt = '100'.", 1, TP),
    ("8546", "CALL 'SYSTEM' ID 'COMMAND' FIELD c.", 1, TP),
    ("8548", "INSERT REPORT p FROM lt.", 1, TP),
    ("8550", "GENERATE SUBROUTINE POOL lt NAME n.", 1, TP),
    ("8552", "OPEN DATASET p FOR OUTPUT IN TEXT MODE ENCODING DEFAULT FILTER 'x'.", 1, TP),
    ("8572", "SUBMIT zrep USER 'BATCH' VIA JOB j NUMBER n AND RETURN.", 1, TP),
    ("8574", "CALL TRANSACTION p_tcode.", 1, TP),
    ("8574", "CALL TRANSACTION 'SE38'.", 1, FP),
    ("8586", "CALL FUNCTION p_name.", 1, TP),
    # --- review only
    ("7766", "FORM f.\nENDFORM.", 1, RV),
]


def main():
    bad = 0
    for rid, src, line, want in CASES:
        ctx = ac.Ctx(src.splitlines())
        name, fn = ac.RULES.get(rid) or (None, ac.chk_manual(ac.MANUAL_BY_ID.get(rid, "?")))
        got, why, ev = fn(ctx, line)
        if got != want:
            bad += 1
            print(f"FAIL {rid} line {line}: expected {want}, got {got} - {why}\n     src: {src!r}")
    print(f"{len(CASES) - bad}/{len(CASES)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
