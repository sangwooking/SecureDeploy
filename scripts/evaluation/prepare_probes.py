"""Exploratory probes after baseline observation; never call these blind holdouts."""
import json
import pathlib
import sys


def prepare(root):
    root.mkdir(parents=True, exist_ok=False)
    cases=[]

    def add(name, area, truth, rule, support, files):
        directory=root/name
        directory.mkdir()
        for name_in_project, text in files.items():
            path=directory/name_in_project
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(text)
        cases.append(dict(id=name,area=area,truth=truth,rule=rule,support=support))

    add("npm-pretty-old","supply-chain","DANGEROUS","VULNERABLE_NPM_DEPENDENCY","STRUCTURAL",
        {"package.json":json.dumps({"dependencies":{"lodash":"4.17.10"}},indent=2)})
    add("npm-pretty-range","supply-chain","UNKNOWN","VULNERABLE_NPM_DEPENDENCY","STRUCTURAL",
        {"package.json":json.dumps({"dependencies":{"lodash":"^4.17.10"}},indent=2)})
    add("java-split-construction","input","DANGEROUS","DANGEROUS_SQL","PATTERN_ONLY",
        {"src/main/java/demo/Lookup.java":'class Lookup {void get(String input){\nString query="SELECT id FROM items WHERE label=";\nquery += input;\nconnection.prepareStatement(query).execute();\n}}'})
    add("java-fixed-statement","input","SAFE","DANGEROUS_SQL","PATTERN_ONLY",
        {"src/main/java/demo/Lookup.java":'class Lookup {void get(){\njava.sql.Statement query=connection.createStatement();\nquery.execute("SELECT 1");\n}}'})
    add("ssrf-renamed-nested","input","DANGEROUS","TS_SSRF_INPUT_FLOW","DATA_FLOW_PARTIAL",
        {"functions/api/relay.ts":'export async function onRequest({request}){const parcel=await request.json();const address=parcel.destination;return fetch(address);}'})
    add("sql-split-helper","input","DANGEROUS","PY_SQL_INPUT_FLOW","DATA_FLOW_PARTIAL",
        {"orders/views.py":"from rest_framework.decorators import api_view\nfrom .repository import lookup\n@api_view(['POST'])\ndef search(request):\n    return lookup(request.POST['filter'])",
         "orders/repository.py":"from django.db import connection\ndef lookup(value):\n    query=f'SELECT id FROM items WHERE label={value}'\n    with connection.cursor() as database:\n        database.execute(query)"})
    (root/"manifest.json").write_text(json.dumps(dict(schemaVersion=1,provenance="exploratory post-baseline variations, not a holdout",cases=cases),indent=2))
    print("exploratory_cases="+str(len(cases)))


if __name__=="__main__":
    prepare(pathlib.Path(sys.argv[1]))
