"""Run: python3 test_sapui5_checkers.py   (no server needed)"""
import sys
import sapui5_checkers as ui

TP, FP, RV = ui.TP, ui.FP, ui.RV
DEF = 'sap.ui.define(["sap/m/Button","sap/ui/model/json/JSONModel","sap/ui/model/odata/v2/ODataModel"], function(Button, JSONModel, ODataModel) {\n'
# (rule, kind, source, line, expected)
CASES = [
    ("1020600", "js", "jQuery.sap.require('sap.m.Button');", 1, TP),
    ("1020600", "js", "sap.ui.define(['jquery.sap.global'], function(jQuery){});", 1, TP),
    ("1020600", "js", "// jQuery.sap.require('x');\nvar a = 1;", 1, FP),
    ("1020600", "js", "var s = 'jQuery.sap.log';", 1, FP),
    ("1020600", "js", "var a = 1;", 1, FP),
    ("1020602", "js", "var m = new sap.ui.model.odata.ODataModel('/svc');", 1, TP),
    ("1020602", "js", "sap.ui.define(['sap/ui/model/odata/ODataModel'], function(M){});", 1, TP),
    ("1020602", "js", "sap.ui.define(['sap/ui/model/odata/v2/ODataModel'], function(M){});", 1, FP),
    ("1020602", "json", '{"sap.ui5":{"models":{"":{"type":"sap.ui.model.odata.ODataModel"}}}}', 1, TP),
    ("1020618", "js", "var s = jQuery.sap.storage(jQuery.sap.storage.Type.local);", 1, TP),
    ("1020618", "js", "var s = jQuery.sap.storage(jQuery.sap.storage.Type.session);", 1, FP),
    ("1020614", "js", "console.log('x');", 1, TP),
    ("1020614", "js", "console.error('x');", 1, RV),
    ("1020614", "js", "/* console.log('x'); */\nvar a;", 1, FP),
    ("1020614", "js", "var s = 'console.log(x)';", 1, FP),
    # unnamed model
    ("1020604", "js", DEF + "var o = new ODataModel('/svc');\nthis.getView().setModel(o);", 3, TP),
    ("1020604", "js", DEF + "var o = new ODataModel('/svc');\nthis.getView().setModel(o, 'main');", 3, FP),
    ("1020604", "js", DEF + "var o = new JSONModel({});\nthis.getView().setModel(o);", 3, FP),
    ("1020604", "js", DEF + "this.setModel(new ODataModel('/svc'));", 2, TP),
    ("1020604", "js", DEF + "this.setModel(oFoo);", 2, RV),
    ("1020604", "json", '{\n "models": {\n  "": {\n   "dataSource": "mainService"\n  }\n }\n}', 3, TP),
    ("1020604", "json", '{\n "models": {\n  "": {\n   "type": "sap.ui.model.json.JSONModel"\n  }\n }\n}', 3, FP),
    # async
    ("1020606", "html", '<html>\n<script id="sap-ui-bootstrap" src="resources/sap-ui-core.js"\n data-sap-ui-theme="x"></script>', 2, TP),
    ("1020606", "html", '<script id="b" src="resources/sap-ui-core.js" data-sap-ui-async="true"></script>', 1, FP),
    ("1020606", "json", '{\n "rootView": {\n  "viewName": "a.App",\n  "async": true\n }\n}', 2, FP),
    ("1020606", "json", '{\n "rootView": {\n  "viewName": "a.App"\n }\n}', 2, TP),
    ("1020606", "json", '{\n "routing": {\n  "config": {\n   "async": false\n  }\n }\n}', 2, TP),
    ("1020606", "js", "var v = sap.ui.xmlview('a.View');", 1, TP),
    ("1020606", "js", "var v = sap.ui.view({viewName: 'a.V', type: 'XML', async: true});", 1, FP),
    ("1020606", "js", "jQuery.sap.require('sap.m.Button');", 1, TP),
    ("1020606", "js", "XMLView.create({viewName: 'a.V'});", 1, FP),
    # hardcoded IDs
    ("1020608", "js", "var c = sap.ui.getCore().byId('myBtn');", 1, TP),
    ("1020608", "js", DEF + "var b = new Button('btn1', {text: 'x'});", 2, TP),
    ("1020608", "js", DEF + "var b = new Button({id: 'btn1', text: 'x'});", 2, TP),
    ("1020608", "js", DEF + "var b = new Button({text: 'x'});", 2, FP),
    ("1020608", "js", DEF + "var m = new JSONModel('data.json');", 2, FP),
    ("1020608", "js", "var c = this.byId('myBtn');", 1, FP),
    ("1020608", "js", "var c = document.getElementById('x');", 1, TP),
    # duplicate OData model
    ("1020610", "js", "var a = new ODataModel('/svc/A');\nvar b = new ODataModel('/svc/A');", 1, TP),
    ("1020610", "js", "var a = new ODataModel('/svc/A');\nvar b = new ODataModel('/svc/B');", 1, RV),
    ("1020610", "json", '{\n "sap.app":{"dataSources":{"a":{"uri":"/s/"},"b":{"uri":"/s/"}}},\n "sap.ui5":{"models":{\n "m1":{"dataSource":"a"},\n "m2":{"dataSource":"a"}}}}', 5, TP),
    ("1020610", "json", '{\n "sap.app":{"dataSources":{"a":{"uri":"/s/"}}},\n "sap.ui5":{"models":{\n "m1":{"dataSource":"a"}}}}', 4, RV),
    # override control methods
    ("1020612", "js", "sap.m.Button.prototype.onAfterRendering = function() {};", 1, TP),
    ("1020612", "js", DEF + "Button.prototype.foo = function() {};", 2, TP),
    ("1020612", "js", DEF + "MyClass.prototype.foo = function() {};", 2, FP),
    ("1020612", "js", DEF + "var b = new Button();\nb.onclick = function() {};", 3, TP),
    ("1020612", "js", DEF + "var b = new Date();\nb.foo = function() {};", 3, FP),
    ("1020612", "js", "var a = 1;", 1, FP),
    # CRUD keys
    ("1020616", "js", "oModel.update(\"/Products('\" + sId + \"')\", oData);", 1, TP),
    ("1020616", "js", "oModel.update(oModel.createKey('/Products', {Id: 1}), oData);", 1, FP),
    ("1020616", "js", "var sPath = oModel.createKey('/Products', {Id: 1});\noModel.remove(sPath);", 2, FP),
    ("1020616", "js", "var sPath = '/Products(' + sId + ')';\noModel.remove(sPath);", 2, TP),
    ("1020616", "js", "oModel.create('/Products', oData);", 1, FP),
    ("1020616", "js", "var sPath = oCtx.getPath();\noModel.update(sPath, oData);", 2, FP),
    ("1020616", "js", "aList.remove(x);", 1, RV),
]


def main():
    bad = 0
    for rid, kind, src, line, want in CASES:
        ctx = ui.JsCtx(src.splitlines(), kind)
        got, why, ev = ui.RULES[rid][1](ctx, line)
        if got != want:
            bad += 1
            print(f"FAIL {rid} [{kind}] line {line}: expected {want}, got {got} - {why}\n     src: {src!r}")
    print(f"{len(CASES) - bad}/{len(CASES)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
