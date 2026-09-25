"""System-1 classifier abstraction.

Backends:
  - typesafe:  real JEV model via typesafe-sdk (needs TYPESAFE_API_KEY)
  - openrouter: LLM emulating the Noul/Choice/Score interface (demo fallback)
"""

import json
import os
import re
from dataclasses import dataclass, field

import httpx

from .questions import question_set


@dataclass
class Classification:
    nouls: dict[str, float] = field(default_factory=dict)
    choices: dict[str, dict] = field(default_factory=dict)  # name -> {choice, probabilities, confidence}
    scores: dict[str, dict] = field(default_factory=dict)   # name -> {score, confidence}
    backend: str = "unknown"


class TypeSafeBackend:
    name = "typesafe-jev"

    def __init__(self):
        from typesafe_sdk import Choice, Noul, Score, TypeSafeClient

        self._Choice, self._Noul, self._Score = Choice, Noul, Score
        self.client = TypeSafeClient()

    def noul(self, state: str, instructions: str) -> float:
        resp = self.client.system_one(state=state, questions={"gate": self._Noul(instructions=instructions)})
        return float(resp.answers["gate"].noul)

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
        resp = self.client.system_one(state=state, questions=sdk_qs)
        out = Classification(backend=self.name)
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
        return out


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
        answers = self._decide(state, qs)["answers"]
        out = Classification(backend=self.name)
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
        r = self.http.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.key}"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You emulate a System-1 calibrated classification model for security log triage. Output strict JSON only."},
                    {"role": "user", "content": prompt},
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0,
            },
        )
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
        data = json.loads(re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M))
        out = Classification(backend=self.name)
        out.nouls = {k: float(v) for k, v in data.get("nouls", {}).items()}
        out.choices = data.get("choices", {})
        out.scores = data.get("scores", {})
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


def noul_gate(classifier, state: str, instructions: str) -> float:
    """Single yes/no question — used for the SOAR action guardrail (Auto Mode pattern)."""
    if hasattr(classifier, "noul"):
        return classifier.noul(state, instructions)
    r = classifier.http.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {classifier.key}"},
        json={
            "model": classifier.model,
            "messages": [
                {"role": "system", "content": "You emulate a System-1 calibrated classifier. Output strict JSON only."},
                {"role": "user", "content": (
                    f"STATE:\n{state}\n\nQuestion (answer with calibrated probability that the statement is true):\n"
                    f"{instructions}\n\nReturn ONLY JSON: {{\"noul\": <probability 0-1>}}"
                )},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
        },
        timeout=60,
    )
    r.raise_for_status()
    text = r.json()["choices"][0]["message"]["content"]
    return float(json.loads(re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M))["noul"])
