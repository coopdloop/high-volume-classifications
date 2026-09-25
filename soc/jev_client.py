"""System-1 classifier abstraction.

Backends:
  - typesafe:       real JEV via typesafe-sdk (TYPESAFE_API_KEY)
  - jev-openrouter: real JEV via OpenRouter Decisions API (OPENROUTER_API_KEY)
  - emulated:       chat LLM approximating the Noul/Choice/Score interface

Every classify() returns a Classification carrying the full raw answer payload
(incl. probability maps), model id, latency, and cost for observability.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field

import httpx

from .questions import question_set


@dataclass
class Classification:
    nouls: dict[str, float] = field(default_factory=dict)
    choices: dict[str, dict] = field(default_factory=dict)  # name -> {choice, probabilities, confidence}
    scores: dict[str, dict] = field(default_factory=dict)   # name -> {score, confidence}
    backend: str = "unknown"
    model: str = ""
    latency_ms: float = 0.0
    cost: float | None = None
    raw: dict = field(default_factory=dict)  # full answer payload incl. probability maps


class TypeSafeBackend:
    name = "typesafe-jev"

    def __init__(self):
        from typesafe_sdk import Choice, Noul, Score, TypeSafeClient

        self._Choice, self._Noul, self._Score = Choice, Noul, Score
        self.client = TypeSafeClient()
        self.model = os.getenv("JEV_MODEL", "jev-latest")

    def classify(self, state: str) -> Classification:
        qs = question_set()
        sdk_qs = {}
        for name, q in qs.items():
            if q["type"] == "noul":
                sdk_qs[name] = self._Noul(instructions=q["instructions"])
            elif q["type"] == "choice":
                sdk_qs[name] = self._Choice(instructions=q["instructions"], criteria=q["criteria"])
            else:
                sdk_qs[name] = self._Score(instructions=q["instructions"], criteria=q["criteria"])
        t0 = time.time()
        resp = self.client.system_one(state=state, questions=sdk_qs)
        out = Classification(backend=self.name, model=self.model, latency_ms=(time.time() - t0) * 1000)
        for name, q in qs.items():
            ans = resp.answers[name]
            conf = float(getattr(ans, "confidence", 1.0))
            if q["type"] == "noul":
                out.nouls[name] = float(ans.noul)
            elif q["type"] == "choice":
                probs = {k: float(v) for k, v in getattr(ans, "probabilities", {}).items()}
                out.choices[name] = {"choice": ans.choice, "probabilities": probs, "confidence": conf}
            else:
                out.scores[name] = {"score": float(ans.score) + 1.0, "confidence": conf}  # 0-based -> 1..N
        out.raw = {"nouls": out.nouls, "choices": out.choices, "scores": out.scores}
        return out

    def noul(self, state: str, instructions: str) -> float:
        resp = self.client.system_one(state=state, questions={"gate": self._Noul(instructions=instructions)})
        return float(resp.answers["gate"].noul)


class JevOpenRouterBackend:
    """Real JEV via OpenRouter's Decisions API (alpha)."""

    name = "jev-openrouter"
    ENDPOINT = "https://openrouter.ai/api/alpha/decisions"

    def __init__(self):
        self.key = os.environ["OPENROUTER_API_KEY"]
        self.model = os.getenv("JEV_MODEL", "typesafe/jev-1.13")
        self.http = httpx.Client(timeout=60)

    def _decide(self, state: str, questions: dict) -> dict:
        r = self.http.post(
            self.ENDPOINT,
            headers={"Authorization": f"Bearer {self.key}"},
            json={"model": self.model, "state": state, "questions": questions},
        )
        r.raise_for_status()
        return r.json()

    def classify(self, state: str) -> Classification:
        qs = question_set()
        t0 = time.time()
        data = self._decide(state, qs)
        answers = data["answers"]
        usage = data.get("usage") or {}
        out = Classification(
            backend=self.name,
            model=data.get("model", self.model),
            latency_ms=(time.time() - t0) * 1000,
            cost=usage.get("cost"),
            raw=answers,
        )
        for name, q in qs.items():
            a = answers[name]
            if q["type"] == "noul":
                out.nouls[name] = float(a["noul"])
            elif q["type"] == "choice":
                out.choices[name] = {
                    "choice": a["choice"],
                    "probabilities": a.get("probabilities", {}),
                    "confidence": float(a.get("confidence", 1.0)),
                }
            else:
                # JEV score is a 0-based index over criteria; normalize to 1..N
                out.scores[name] = {
                    "score": float(a["score"]) + 1.0,
                    "confidence": float(a.get("confidence", 1.0)),
                }
        return out

    def noul(self, state: str, instructions: str) -> float:
        answers = self._decide(state, {"gate": {"type": "noul", "instructions": instructions}})["answers"]
        return float(answers["gate"]["noul"])


class OpenRouterBackend:
    name = "openrouter-emulated"

    def __init__(self):
        self.key = os.environ["OPENROUTER_API_KEY"]
        self.model = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
        self.http = httpx.Client(timeout=60)

    def _chat(self, messages: list[dict]) -> dict:
        r = self.http.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.key}"},
            json={
                "model": self.model,
                "messages": messages,
                "response_format": {"type": "json_object"},
                "temperature": 0,
            },
        )
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _parse(text: str) -> dict:
        return json.loads(re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M))

    def classify(self, state: str) -> Classification:
        qs = question_set()
        prompt = (
            "STATE:\n" + state + "\n\nQUESTIONS:\n" + json.dumps(qs, indent=2) + "\n\n"
            "Return ONLY JSON of the form:\n"
            '{"nouls": {<noul question>: probability 0-1}, '
            '"choices": {<choice question>: {"choice": <option key>, "probabilities": {key: p}, "confidence": 0-1}}, '
            '"scores": {<score question>: {"score": <float, 1-based within criteria range>, "confidence": 0-1}}}\n'
            "Answer every question. Be calibrated: low confidence when the evidence is thin."
        )
        t0 = time.time()
        data = self._chat([
            {"role": "system", "content": "You emulate a System-1 calibrated classification model for security log triage. Output strict JSON only."},
            {"role": "user", "content": prompt},
        ])
        usage = data.get("usage") or {}
        parsed = self._parse(data["choices"][0]["message"]["content"])
        out = Classification(
            backend=self.name,
            model=self.model,
            latency_ms=(time.time() - t0) * 1000,
            cost=usage.get("cost"),
            raw=parsed,
        )
        out.nouls = {k: float(v) for k, v in parsed.get("nouls", {}).items()}
        out.choices = parsed.get("choices", {})
        out.scores = parsed.get("scores", {})
        return out


def get_classifier():
    """Backend selection: SYSTEM1_BACKEND=auto|typesafe|jev-openrouter|emulated.

    auto: TypeSafe direct (if TYPESAFE_API_KEY + sdk) -> real JEV via OpenRouter
    (if OPENROUTER_API_KEY). 'emulated' opts into the chat-LLM approximation.
    """
    backend = os.getenv("SYSTEM1_BACKEND", "auto")
    if backend in ("auto", "typesafe") and os.getenv("TYPESAFE_API_KEY"):
        try:
            return TypeSafeBackend()
        except ImportError:
            if backend == "typesafe":
                raise SystemExit("pip install typesafe-sdk for SYSTEM1_BACKEND=typesafe")
            print("[jev] typesafe-sdk not installed; trying JEV via OpenRouter")
    if backend in ("auto", "jev-openrouter") and os.getenv("OPENROUTER_API_KEY"):
        return JevOpenRouterBackend()
    if backend == "emulated" and os.getenv("OPENROUTER_API_KEY"):
        return OpenRouterBackend()
    raise SystemExit("Set OPENROUTER_API_KEY (JEV via OpenRouter) or TYPESAFE_API_KEY in .env")


def noul_gate(classifier, state: str, instructions: str, record: dict | None = None) -> float:
    """Single yes/no question — the SOAR action guardrail (Auto Mode pattern).

    If `record` (a dict) is passed, it is filled with model/latency/cost/raw
    for observability logging.
    """
    t0 = time.time()
    if isinstance(classifier, TypeSafeBackend):
        prob = classifier.noul(state, instructions)
        meta = {"model": classifier.model, "cost": None, "raw": {"gate": prob}}
    elif isinstance(classifier, JevOpenRouterBackend):
        data = classifier._decide(state, {"gate": {"type": "noul", "instructions": instructions}})
        prob = float(data["answers"]["gate"]["noul"])
        meta = {
            "model": data.get("model", classifier.model),
            "cost": (data.get("usage") or {}).get("cost"),
            "raw": data["answers"],
        }
    else:
        data = classifier._chat([
            {"role": "system", "content": "You emulate a System-1 calibrated classifier. Output strict JSON only."},
            {"role": "user", "content": (
                f"STATE:\n{state}\n\nQuestion (answer with calibrated probability that the statement is true):\n"
                f"{instructions}\n\nReturn ONLY JSON: {{\"noul\": <probability 0-1>}}"
            )},
        ])
        prob = float(classifier._parse(data["choices"][0]["message"]["content"])["noul"])
        meta = {"model": classifier.model, "cost": (data.get("usage") or {}).get("cost"), "raw": {"gate": prob}}
    if record is not None:
        record.update({
            "backend": classifier.name,
            "latency_ms": (time.time() - t0) * 1000,
            **meta,
        })
    return prob
