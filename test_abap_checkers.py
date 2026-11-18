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
    ("7520", "READ TABLE lt ASSIGNING <fs> INDEX 1.\nIF <fs> IS ASSIGNED.\nENDIF.", 1, RV),
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
    ("7868", "WRITE 1.", 1, RV),
    # --- 7884 inspection switched off, 7526 hard-coded path, 7788 / 8028 reuse
    ("7884", "SELECT * FROM mara INTO ls.  \"#EC CI_NOWHERE\nENDSELECT.", 1, TP),
    ("7884", "DATA lv TYPE i ##NEEDED.", 1, TP),
    ("7884", "DATA lv TYPE i.", 1, RV),
    ("7884", "WRITE 'a ##b'.", 1, RV),
    ("7526", "OPEN DATASET 'C:\\temp\\out.txt' FOR OUTPUT IN TEXT MODE ENCODING DEFAULT.", 1, TP),
    ("7526", "lv_file = '/usr/sap/trans/data/x.txt'.", 1, TP),
    ("7526", "lv_file = '\\\\srv\\share\\x.txt'.", 1, TP),
    ("7526", "lv = '/BIC/AZ1'.", 1, RV),
    ("7526", "lv = '/sap/opu/odata/srv'.", 1, RV),
    ("7526", "lv = 'hello'.", 1, RV),
    ("7788", "TRY.\n  CATCH cx_root.\nENDTRY.", 2, TP),
    ("7788", "TRY.\n  CATCH cx_root.\n    WRITE 1.\nENDTRY.", 2, FP),
    ("8028", "CASE a.\n  WHEN 1.\n    WRITE 1.\nENDCASE.", 1, TP),
    ("8028", "CASE a.\n  WHEN 1.\n    WRITE 1.\n  WHEN OTHERS.\n    WRITE 2.\nENDCASE.", 1, FP),
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
    ("7518", "CASE a.\n  WHEN 1.\n    WRITE 1.\n  WHEN OTHERS.\n    WRITE 2.\nENDCASE.", 1, FP),
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
    ("7906", "IF sy-datum = lv_d.\nENDIF.", 1, RV),
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
    ("8582", "CALL FUNCTION 'Z_FM'.", 1, RV),
    ("8578", "MODIFY SCREEN.", 1, FP),
    ("8578", "MODIFY ztab FROM ls.", 1, RV),
    ("8422", "FORM f ON COMMIT.\n  COMMIT WORK.\nENDFORM.", 2, TP),
    # --- error handling
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1.", 1, TP),
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.", 1, TP),   # EXCEPTIONS declared, SY-SUBRC never read
    ("8120", "TRY.\n  CALL FUNCTION 'Z' EXPORTING a = 1.\nCATCH cx_a.\nENDTRY.", 2, FP),
    ("8120", "TRY.\nCATCH cx_a.\n  CALL FUNCTION 'Z' EXPORTING a = 1.\nENDTRY.", 3, TP),
    ("8122", "CALL METHOD o->m.", 1, TP),
    # --- keyword rules
    ("7524", "BREAK-POINT.", 1, TP),
    ("7524", "BREAK jdoe.", 1, TP),
    ("7524", "* BREAK-POINT.\nWRITE 1.", 1, FP),
    ("7528", "ON CHANGE OF a.\nENDON.", 1, TP),
    ("7592", "SELECT a FROM t INTO TABLE lt ORDER BY a.", 1, TP),
    ("7592", "SELECT a FROM t INTO TABLE lt.", 1, RV),
    ("7594", "SELECT DISTINCT a FROM t INTO TABLE lt.", 1, TP),
    ("7870", "SELECT a FROM t INTO TABLE lt WHERE b NOT LIKE 'X%'.", 1, TP),
    ("7872", "SELECT a FROM t INTO TABLE lt WHERE b IS NULL.", 1, TP),
    ("7874", "SELECT a FROM (lv_tab) INTO TABLE lt WHERE (lv_where).", 1, TP),
    ("7874", "SELECT a FROM t INTO TABLE lt WHERE b IN ('A','B') AND c = COUNT( * ).", 1, RV),
    ("7876", "SELECT SINGLE a FROM t INTO l FOR UPDATE.", 1, TP),
    ("7882", "EXEC SQL.\n  select 1 from dual\nENDEXEC.", 1, TP),
    ("7886", "SYSTEM-CALL CREATE CLASS-OBJECT.", 1, TP),
    ("7806", "SELECT a FROM t INTO TABLE lt GROUP BY a.", 1, TP),
    ("7808", "SELECT a FROM t INTO TABLE lt WHERE b IN ( SELECT b FROM u ).", 1, TP),
    ("8116", "CALL 'C_FOO' ID 'X' FIELD y.", 1, TP),
    ("8118", "CALL FUNCTION 'RFC_ABAP_INSTALL_AND_RUN'.", 1, TP),
    ("8130", "SELECT a FROM t INTO TABLE lt %_HINTS ORACLE 'FOO'.", 1, TP),
    ("8412", "TRY.\nCATCH cx_root INTO lx.\nENDTRY.", 2, TP),
    ("8412", "TRY.\nCATCH cx_root_foo INTO lx.\nENDTRY.", 2, RV),
    ("8426", "CALL 'C_DB_EXECUTE' ID 'STATLEN' FIELD l.", 1, TP),
    ("8432", "SELECT * FROM t CLIENT SPECIFIED INTO TABLE lt WHERE mandt = '100'.", 1, TP),
    ("8546", "CALL 'SYSTEM' ID 'COMMAND' FIELD c.", 1, TP),
    ("8548", "INSERT REPORT p FROM lt.", 1, TP),
    ("8550", "GENERATE SUBROUTINE POOL lt NAME n.", 1, TP),
    ("8552", "OPEN DATASET p FOR OUTPUT IN TEXT MODE ENCODING DEFAULT FILTER 'x'.", 1, TP),
    ("8572", "SUBMIT zrep USER 'BATCH' VIA JOB j NUMBER n AND RETURN.", 1, TP),
    ("8574", "CALL TRANSACTION p_tcode.", 1, TP),
    ("8574", "CALL TRANSACTION 'SE38'.", 1, RV),
    ("8586", "CALL FUNCTION p_name.", 1, TP),
    # --- review only
    ("7766", "FORM f.\nENDFORM.", 1, RV),

    # --- regression tests taken from real code (SAP billing/sales user exits) -----------------------
    # 7520: an IS INITIAL test of an UNRELATED variable is not a return-code check
    ("7520", "UPDATE vbap SET awahr = 100 WHERE vbeln = x.\nIF CVBAP-POSNR IS INITIAL.\n  MESSAGE a247 WITH '151'.\nENDIF.", 1, TP),
    # 7520: 'sy-subrc = 0.' ASSIGNS the return code, it does not check it
    ("7520", "IF NOT vbak IS INITIAL.\n  SELECT SINGLE vkorg FROM zsd INTO l_vkorg WHERE vkorg = vbak-vkorg.\nENDIF.\nSY-SUBRC = 0.\nCHECK analyze_mode IS INITIAL.", 2, TP),
    # 7520: SY-SUBRC read in a WHILE condition IS a check
    ("7520", "READ TABLE cvbpa WITH KEY cvbpa(19) BINARY SEARCH.\n* copy the partner\nWHILE cvbpa-posnr = cvbap-vgpos AND\n      SY-SUBRC = 0.\nENDWHILE.", 1, FP),
    # 7520: testing the result variable itself counts
    ("7520", "SELECT SINGLE mwsk1 FROM t INTO lv_mwsk1 WHERE a = 1.\nCHECK lv_mwsk1 IS NOT INITIAL.", 1, RV),
    # 8120 / 8122: EXCEPTIONS only help if the return code is read afterwards
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.\nIF sy-subrc <> 0.\n  RETURN.\nENDIF.", 1, FP),
    ("8120", "CALL FUNCTION 'APPL_LOG_INIT'  ##FM_SUBRC_OK\n  EXPORTING object = o\n  EXCEPTIONS object_not_found = 1. \"#EC CI_SUBRC\n\nCALL FUNCTION 'MESSAGES_INITIALIZE'.", 1, TP),
    ("8120", "CALL FUNCTION 'MESSAGES_INITIALIZE'.", 1, TP),
    ("8122", "CALL METHOD o->m EXCEPTIONS foo = 1.\nIF sy-subrc = 0.\nENDIF.", 1, RV),
    ("8122", "CALL METHOD o->m EXCEPTIONS foo = 1.\nWRITE 1.", 1, TP),
    # 7542: 'IF t[] IS INITIAL ... EXIT. ENDIF.' is a real guard
    ("7542", "IF t[] IS INITIAL.\n  PERFORM f_message.\n  EXIT.\nENDIF.\nSORT t BY a.\nSELECT * FROM x INTO TABLE r FOR ALL ENTRIES IN t WHERE a = t-a.", 6, FP),
    # 7542: ...but only if the empty branch really leaves
    ("7542", "IF t[] IS INITIAL.\n  WRITE 1.\nENDIF.\nSELECT * FROM x INTO TABLE r FOR ALL ENTRIES IN t WHERE a = t-a.", 4, TP),
    ("7542", "IF t[] IS INITIAL.\n  LOOP AT x INTO y.\n    EXIT.\n  ENDLOOP.\nENDIF.\nSELECT * FROM x INTO TABLE r FOR ALL ENTRIES IN t WHERE a = t-a.", 6, TP),
    ("7542", "IF t[] IS INITIAL.\n  WRITE 1.\nELSE.\n  SELECT * FROM x INTO TABLE r FOR ALL ENTRIES IN t WHERE a = t-a.\nENDIF.", 4, FP),
    ("7542", "IF NOT t[] IS INITIAL.\n  SELECT * FROM x INTO TABLE r FOR ALL ENTRIES IN t WHERE a = t-a.\nENDIF.", 2, FP),
    ("7542", "IF t[] IS NOT INITIAL.\nENDIF.\nSELECT * FROM x INTO TABLE r FOR ALL ENTRIES IN t WHERE a = t-a.", 3, TP),
    ("7542", "CHECK t[] IS NOT INITIAL.\nSELECT * FROM x INTO TABLE r FOR ALL ENTRIES IN t WHERE a = t-a.", 2, FP),
    # a copy of SY-SUBRC into a result field reads it but does not test it -> REVIEW, not a proven false positive
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.\nt_result-zzcode = sy-subrc.", 1, RV),
    ("7520", "READ TABLE lt INTO ls INDEX 1.\nlv_rc = sy-subrc.", 1, RV),
    # --- regression tests from real code (anchoring and parsing details seen on a real server) ------------
    ("1101018", "RETURN\n  SELECT a, SUM( b ) AS s\n    FROM t\n    GROUP BY a.", 1, TP),                       # RETURN SELECT ...
    ("7882", "DO.\n  EXEC \"#EC CI_EXECSQL\n    SQL.\n    select 1 from dual\n  ENDEXEC.\nENDDO.", 1, TP),     # reported on the DO. before
    ("7882", "DO.\n  WRITE 1.\nENDDO.", 1, RV),
    ("7514", "* Extractor header\nINCLUDE_NAME ZX .\n*&---\n", 1, TP),                                       # extractor pseudo-statement only
    ("7514", "INCLUDE_NAME ZX .\nWRITE 1.\n", 1, FP),
    ("7858", "*&-----\n*&  Form  X\n*&-----\nFORM x USING VALUE(p) TYPE i.\nENDFORM.", 2, TP),             # reported on the comment header
    ("7536", "LOOP AT lt INTO ls WHERE a = 1.\n  AT NEW b.\n  ENDAT.\nENDLOOP.", 2, TP),                     # reported on the AT line
    ("7536", "LOOP AT lt INTO ls.\n  AT NEW b.\n  ENDAT.\nENDLOOP.", 2, FP),
    ("7820", "SELECT a FROM t1 AS a INNER JOIN t2 AS b ON b~x = @lv INTO TABLE @lt.", 1, RV),            # ON does not relate the tables
    ("7820", "SELECT a FROM t1 AS a INNER JOIN t2 AS b ON b~x = a~x INTO TABLE @lt.", 1, FP),
    ("7524", "* BREAK-POINT.\nWRITE 1.", 1, FP),                                                         # reported line is a comment
    # --- a comment/string verdict must be PROVEN: every occurrence is inside a comment or a literal ----------
    ("8130", "SELECT a FROM t INTO TABLE lt WHERE b = 'x %_HINTS y'.", 1, FP),                      # only inside a literal
    ("8130", "SELECT a FROM t INTO TABLE lt  \" %_HINTS ORACLE 'x'\n  WHERE b = 1.", 1, FP),        # only in a comment
    ("8130", "SELECT a FROM t INTO TABLE lt WHERE b = 'x'  %_HINTS ORACLE 'FOO'.", 1, TP),         # real code
    # SQLScript (no '.' terminators) merges into one ABAP "statement": real GROUP BY must never become a false positive
    ("1101018", "itab = select a, count(*) AS c\n  FROM t\n  GROUP BY a;\nENDMETHOD.", 1, RV),
    # long comment banner above a FORM (reported line is in the banner)
    ("7858", "*&" + "-" * 20 + "\n" + "*&  comment\n" * 12 + "FORM x USING VALUE(p) TYPE i.\nENDFORM.", 2, TP),
    # --- an EMPTY "WHEN OTHERS." is how CAST sees a missing one (32 of 32 flagged cases on a real application)
    ("7518", "CASE a.\n  WHEN 1.\n    WRITE 1.\n  WHEN OTHERS.\nENDCASE.", 1, TP),
    ("7518", "CASE <lfs>.\n\n* comment\n  WHEN lc_z.\n    PERFORM f.\n\n  WHEN OTHERS.\n\nENDCASE.", 1, TP),
    # --- compound assignments (x += y) are statements: the block is not empty
    ("8106", "IF t-beknz = 'S'.\n  w_debit += t-wog011.\nELSE.\n  w_credit += t-wog011.\nENDIF.", 1, FP),
    ("8126", "SELECT * FROM cosp INTO ls WHERE a = 1.\n  w_t += ls-wtg012.\n  w_u += ls-wtg013.\nENDSELECT.", 1, FP),
    # --- regression tests from a full real run (15,555 violations): a check must belong to THE statement ----------
    # 7520: the IF sy-subrc after ENDLOOP is not a check of the READ inside the loop
    ("7520", "LOOP AT lt_mod INTO ls.\n  READ TABLE t_job INTO ls_job WITH KEY a = 1.\n  IF ls_job-status <> 'D'.\n    w_ko = 'X'.\n    EXIT.\n  ENDIF.\nENDLOOP.\nIF sy-subrc <> 0.\n  w_ko = 'X'.\nENDIF.", 2, TP),
    # 7520: a later statement that sets SY-SUBRC itself takes over
    ("7520", "READ TABLE lt INTO ls INDEX 1.\nASSIGN COMPONENT 'A' OF STRUCTURE ls TO <fs>.\nIF sy-subrc <> 0.\nENDIF.", 1, TP),
    ("7520", "READ TABLE lt INTO ls INDEX 1.\nlv_x = 1.\nIF sy-subrc <> 0.\nENDIF.", 1, FP),
    # 8120: EXCEPTIONS OTHERS = 0 ignores every error; the IF sy-subrc below belongs to the SELECT
    ("8120", "IF a = 1.\n  CALL FUNCTION 'K_ACCOUNTS_READ_TEXTS'\n    EXPORTING i_ktopl = 'PC01'\n    EXCEPTIONS OTHERS = 0.\nENDIF.\nSORT lt BY a.\nSELECT a FROM bkpf INTO TABLE lt WHERE b = 1.\nIF sy-subrc EQ 0.\n  SORT lt BY a.\nENDIF.", 2, TP),
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.\nSELECT a FROM t INTO TABLE lt WHERE b = 1.\nIF sy-subrc = 0.\nENDIF.", 1, TP),
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.\nIF sy-subrc = 0.\n  x = 1.\nELSE.\n  RETURN.\nENDIF.", 1, FP),
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.\nIF sy-subrc = 0.\n  x = 1.\nENDIF.", 1, RV),
    ("8120", "CALL FUNCTION 'Z' EXPORTING a = 1 EXCEPTIONS OTHERS = 1.\nCASE sy-subrc.\n  WHEN 0.\n    x = 1.\n  WHEN OTHERS.\n    RETURN.\nENDCASE.", 1, FP),
    # 8428: the WITH AUTHORITY-CHECK addition of ANOTHER CALL TRANSACTION protects only that call
    ("8428", "CASE x.\n  WHEN 1.\n    CALL TRANSACTION 'YOHAN' WITH AUTHORITY-CHECK.\n  WHEN 2.\n    CALL TRANSACTION 'YVARIANCE'.\nENDCASE.", 5, TP),
    ("8428", "CASE x.\n  WHEN 1.\n    CALL TRANSACTION 'YOHAN' WITH AUTHORITY-CHECK.\nENDCASE.", 3, FP),
    ("8428", "AUTHORITY-CHECK OBJECT 'S_TCODE' ID 'TCD' FIELD 'X'.\nCASE x.\n  WHEN 1.\n    CALL TRANSACTION 'A'.\nENDCASE.", 4, FP),
    # 7512: a FORM whose only statements are compound assignments (*=) is not empty
    ("7512", "FORM f_neg CHANGING p TYPE t.\n  p-a *= -1.\n  p-b *= -1.\nENDFORM.", 1, FP),
    # 7512: CAST reports line 1 of a function module file (the extractor's parameter header); the FUNCTION is below
    ("7512", "BEGIN OF FUNCTION PARAMETERS ZF .\nIMPORTING VALUE(A) TYPE I .\nEND OF FUNCTION PARAMETERS .\nFUNCTION zf.\nENDFUNCTION.", 1, TP),
    ("7512", "BEGIN OF FUNCTION PARAMETERS ZF .\nIMPORTING VALUE(A) TYPE I .\nEND OF FUNCTION PARAMETERS .\nFUNCTION zf.\n  a = 1.\nENDFUNCTION.", 1, FP),
    ("7512", "FORM f.\nENDFORM.", 2, TP),                                                      # reported on ENDFORM
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
    for rid, src, line, frag in [
            ("8106", "IF a = 1.\n  w += 1.\nENDIF.", 1, "compound assignments"),
            ("8106", "IF a IS INITIAL.\n  ASSERT 1 = 0.\nENDIF.", 1, "ASSERT statements"),
            ("8126", "SELECT * FROM t INTO ls.\n  w += ls-x.\nENDSELECT.", 1, "compound assignments"),
            ("7518", "CASE a.\n  WHEN OTHERS.\nENDCASE.", 1, "present but empty"),
            ("7512", "FORM f CHANGING p TYPE t.\n  p-a *= -1.\nENDFORM.", 1, "compound assignments"),
            ("8120", "CALL FUNCTION 'Z' EXCEPTIONS OTHERS = 0.", 1, "explicitly ignores"),
            ("7520", "READ TABLE lt INTO ls INDEX 1.\nCHECK ls IS NOT INITIAL.", 1, "not SY-SUBRC")]:
        got, why, ev = ac.RULES[rid][1](ac.Ctx(src.splitlines()), line)
        if frag not in why:
            bad += 1
            print(f"FAIL reason of {rid}: expected '{frag}' in: {why}")
    for rid, src, line in [("8106", "IF a = 1.\n  w = 1.\nENDIF.", 1),
                           ("8106", "IF a = 1.\n  ASSERT x = 1.\n  w = 1.\nENDIF.", 1)]:
        got, why, ev = ac.RULES[rid][1](ac.Ctx(src.splitlines()), line)
        if "compound" in why or "ASSERT" in why:
            bad += 1
            print(f"FAIL reason of {rid}: a plain assignment must not be described as compound: {why}")
    print(f"{len(CASES) - bad}/{len(CASES)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
