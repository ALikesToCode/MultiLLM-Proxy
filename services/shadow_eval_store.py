"""Private D1 operations with the same fixed SQL for local evaluation tests."""

import json
import re
import time
from contextlib import closing
from pathlib import Path

from services.secret_scan import scan_payload
from services.intelligence_d1_store import request_private_intelligence, using_d1
from services.intelligence_store import IntelligenceStore
from services.shadow_eval_contract import (
    ID, SAMPLE_TTL, default_config, encoded, valid_sample, validate_config,
)

SQL = json.loads((Path(__file__).resolve().parents[1] / "worker/shadow-eval-sql.json").read_text())


class ShadowEvalStore:
    @staticmethod
    def ensure(connection):
        # The account ALTER belongs to AuthService locally and the D1 migration remotely.
        migration = (Path(__file__).resolve().parents[1] / "intelligence-migrations/0014_shadow_eval.sql").read_text()
        for statement in migration[migration.index("CREATE TABLE"):].split(";"):
            if statement.strip():
                connection.execute(statement)
        IntelligenceStore.ensure(connection)

    @classmethod
    def _call(cls, operation, **values):
        if using_d1():
            return request_private_intelligence({"operation": operation, **values}, endpoint="shadow_eval")["result"]
        now = time.time()
        parameters = {"now": now, "cutoff": now - SAMPLE_TTL, "result_cutoff": now - 90 * 86400,
                      "day": int(now // 86400), **values}
        with closing(IntelligenceStore.connect()) as connection:
            cls.ensure(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            cursors = []
            for statement in SQL[operation]:
                names = set(re.findall(r":([a-z_]+)", statement))
                cursor = connection.execute(statement, {name: parameters[name] for name in names})
                if statement.startswith("SELECT"):
                    cursors.append([dict(row) for row in cursor.fetchall()])
                else:
                    cursors.append(cursor.rowcount)
            connection.commit()
        if operation in {"config_get", "sample", "pending"}:
            return json.loads(cursors[0][0]["document"]) if cursors[0] else None
        if operation in {"samples", "results"}:
            return cursors[0]
        if operation in {"claim", "apply"}:
            return cursors[1] == 1
        return cursors[0] == 1

    @classmethod
    def config(cls):
        document = cls._call("config_get")
        if document is None:
            cls._call("config_seed", document=encoded(default_config()))
            document = cls._call("config_get")
        return validate_config(document)

    @classmethod
    def save_config(cls, value, expected):
        value = validate_config(value)
        if not cls._call("config_save", document=encoded(value), expected=encoded(expected)):
            raise ValueError("Evaluation config changed; reload before saving")
        return value

    @classmethod
    def cleanup(cls):
        cls._call("cleanup")

    @classmethod
    def put(cls, sample):
        if not valid_sample(sample, time.time()):
            raise ValueError("Invalid shadow sample")
        for value in (sample["request"], sample["production_answer"]):
            report = scan_payload(value)
            if report["high"] or report["truncated"]:
                raise ValueError("Unsafe shadow sample")
        cls._call("put", id=sample["id"], created_at=sample["created_at"], document=encoded(sample))
        cls.cleanup()

    @classmethod
    def sample(cls, identifier):
        if not isinstance(identifier, str) or not ID.fullmatch(identifier):
            raise ValueError("Invalid sample ID")
        return cls._call("sample", id=identifier)

    @classmethod
    def samples(cls):
        cls.cleanup()
        return cls._call("samples")

    @classmethod
    def pending(cls, task, candidate):
        return cls._call("pending", task=task, candidate=candidate)

    @classmethod
    def lease(cls, run_id):
        return cls._call("lease", run_id=run_id, until=time.time() + 300)

    @classmethod
    def release(cls, run_id):
        cls._call("release", run_id=run_id)

    @classmethod
    def claim(cls, sample, candidate, config, run_id, identifier):
        return cls._call("claim", sample_id=sample["id"], candidate=candidate,
                         config=encoded(config), run_id=run_id, id=identifier)

    @classmethod
    def finish(cls, identifier, result):
        cls._call("finish", id=identifier, document=encoded(result))

    @classmethod
    def results(cls):
        cls.cleanup()
        after = ""
        records = []
        for _ in range(201):
            rows = cls._call("results", after=after)
            records.extend({**json.loads(row["document"]), "_created_at": row["created_at"], "_id": row["id"]} for row in rows)
            if len(rows) < 50:
                return records
            after = rows[-1]["id"]
        raise ValueError("Evaluation result limit exceeded")

    @classmethod
    def purge(cls):
        cls._call("purge")

    @classmethod
    def apply(cls, old, new):
        from services.intelligence_policy import validate_policy
        import uuid

        validate_policy(new)
        # The guard compares the stored bytes, not a normalized policy serialization.
        if using_d1():
            return cls._call("apply", expected=encoded(old), document=encoded(new), id=uuid.uuid4().hex)
        with closing(IntelligenceStore.connect()) as connection:
            IntelligenceStore.ensure(connection)
            row = connection.execute("SELECT document FROM intelligence_policy WHERE id = 1").fetchone()
        if not row or validate_policy(json.loads(row["document"])) != old:
            return False
        return cls._call("apply", expected=row["document"], document=encoded(new), id=uuid.uuid4().hex)
