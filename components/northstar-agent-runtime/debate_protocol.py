"""Debate protocol: AI safety via adversarial argumentation.

Research basis (second-hand):
- Irving, Christiano, Amodei (2018), "AI safety via debate": two agents argue
  opposite sides of a question; a judge - who could not solve the problem
  directly - picks the winner. The claim: judging a debate between experts is
  easier than producing the answer, so a weaker judge can still supervise a
  stronger debater.
- Follow-ups (Anthropic/OpenAI debate work, 2022-2026): dishonest debaters
  lose when the honest side can expose specific falsehoods; the protocol's
  value is structural - enforced alternation, per-round scrutiny, and an
  auditable record of who claimed what.

Design: this module pins the *protocol plumbing*, not a real judge.
:class:`Debate` fixes the topic and round structure. :class:`Judge` scores
each round with a documented lexical heuristic (substance, engagement with
the opponent's prior point, specificity markers, repetition penalty) and
aggregates round verdicts into a :class:`DebateResult`. :func:`run_debate`
runs the whole protocol and returns the result; the ``winner`` field names
the winning side.

Honest scope: the scoring is a lexical heuristic - word overlap and
specificity markers - not semantic judgment. It cannot assess truth: a
confident liar with good vocabulary outscores a terse truth-teller. The
protocol contributes structure (alternation enforcement, per-round verdicts,
audit trail), never correctness. A clean verdict means "side A won the
heuristic scoring", not "side A was right". Real debate safety needs a
competent judge; this module is the scaffold that judge plugs into.

No wall-clock anywhere. All time is caller-supplied integer sequence numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence, Tuple

#: Version pin for the protocol described here.
DEBATE_PROTOCOL_VERSION = "debate-protocol.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.debate-protocol.v1"

#: Fixed debater labels.
DEBATER_A = "a"
DEBATER_B = "b"

#: Winner labels.
WINNER_TIE = "tie"

# A small stopword list for overlap computation (scoring only).
_STOPWORDS = frozenset(
    "a an the and or but of to in on for with is are was were be been it its "
    "this that these those as at by from we you they he she i not no do does "
    "did have has had will would can could should there their our your my"
    .split()
)


def _check_seq(value: object, name: str) -> int:
    """Validate a sequence number: int, non-negative, not a bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int sequence number, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_text(value: object, name: str) -> str:
    """Validate a non-empty text field."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


def _tokens(text: str) -> frozenset:
    """Lowercased content-word tokens for lexical overlap."""
    words = []
    for raw in text.lower().split():
        cleaned = "".join(ch for ch in raw if ch.isalnum())
        if cleaned and cleaned not in _STOPWORDS:
            words.append(cleaned)
    return frozenset(words)


@dataclass(frozen=True)
class Debate:
    """A fixed debate: topic, round count, and identity.

    Frozen. ``rounds`` is a positive int; ``seq`` is caller-supplied (no
    wall-clock).
    """

    debate_id: str
    topic: str
    rounds: int
    seq: int

    def __post_init__(self) -> None:
        _check_text(self.debate_id, "debate_id")
        _check_text(self.topic, "topic")
        if isinstance(self.rounds, bool) or not isinstance(self.rounds, int):
            raise TypeError(f"rounds must be an int, got {type(self.rounds).__name__}")
        if self.rounds <= 0:
            raise ValueError(f"rounds must be positive, got {self.rounds}")
        _check_seq(self.seq, "seq")


@dataclass(frozen=True)
class Argument:
    """One side's argument in one round. Frozen."""

    debater: str
    round_no: int
    text: str
    seq: int

    def __post_init__(self) -> None:
        if self.debater not in (DEBATER_A, DEBATER_B):
            raise ValueError(f"debater must be 'a' or 'b', got {self.debater!r}")
        if isinstance(self.round_no, bool) or not isinstance(self.round_no, int):
            raise TypeError(f"round_no must be an int, got {type(self.round_no).__name__}")
        if self.round_no <= 0:
            raise ValueError(f"round_no must be positive, got {self.round_no}")
        _check_text(self.text, "text")
        _check_seq(self.seq, "seq")


@dataclass(frozen=True)
class RoundVerdict:
    """The judge's per-round scoring. Frozen."""

    round_no: int
    score_a: float
    score_b: float
    winner: str

    def __post_init__(self) -> None:
        if self.winner not in (DEBATER_A, DEBATER_B, WINNER_TIE):
            raise ValueError(f"winner must be 'a', 'b' or 'tie', got {self.winner!r}")

    def as_dict(self) -> dict:
        return {
            "round_no": self.round_no,
            "score_a": self.score_a,
            "score_b": self.score_b,
            "winner": self.winner,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class DebateResult:
    """Full protocol outcome. Frozen. ``winner`` names the winning side."""

    debate_id: str
    topic: str
    rounds: int
    total_a: float
    total_b: float
    round_wins_a: int
    round_wins_b: int
    winner: str
    round_verdicts: Tuple[RoundVerdict, ...]

    def __post_init__(self) -> None:
        if self.winner not in (DEBATER_A, DEBATER_B, WINNER_TIE):
            raise ValueError(f"winner must be 'a', 'b' or 'tie', got {self.winner!r}")

    def as_dict(self) -> dict:
        return {
            "debate_id": self.debate_id,
            "topic": self.topic,
            "rounds": self.rounds,
            "total_a": self.total_a,
            "total_b": self.total_b,
            "round_wins_a": self.round_wins_a,
            "round_wins_b": self.round_wins_b,
            "winner": self.winner,
            "round_verdicts": [v.as_dict() for v in self.round_verdicts],
            "version": DEBATE_PROTOCOL_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class Judge:
    """Scores debate rounds with a documented lexical heuristic.

    Weights are frozen at construction so the same judge scores every round
    identically (deterministic). The heuristic is *not* truth-tracking; see
    the module honest-scope note.
    """

    substance_weight: float = 1.0
    rebuttal_weight: float = 1.0
    evidence_weight: float = 1.0
    repetition_penalty: float = 2.0

    def __post_init__(self) -> None:
        for name in ("substance_weight", "rebuttal_weight", "evidence_weight",
                     "repetition_penalty"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number, got {type(value).__name__}")
            if value < 0:
                raise ValueError(f"{name} must be non-negative, got {value}")

    def score_argument(
        self,
        text: str,
        opponent_prev_text: str | None = None,
        own_prev_text: str | None = None,
    ) -> float:
        """Score one argument. Never raises on well-typed input.

        Components:
        - substance: capped word count (longer substantive arguments score
          higher, up to a cap);
        - rebuttal: lexical overlap with the opponent's previous argument
          (engaging the other side's points, not talking past them);
        - evidence: fraction of tokens containing digits (rough specificity
          marker - figures, dates, citations);
        - repetition penalty: Jaccard similarity with the arguer's own
          previous argument (repeating yourself is penalized).
        """
        _check_text(text, "text")
        tokens = _tokens(text)
        words = text.split()

        substance = min(len(words), 50) / 50.0

        rebuttal = 0.0
        if opponent_prev_text:
            opp_tokens = _tokens(opponent_prev_text)
            if opp_tokens:
                rebuttal = len(tokens & opp_tokens) / len(opp_tokens)

        evidence = 0.0
        if words:
            digit_tokens = sum(1 for w in words if any(ch.isdigit() for ch in w))
            evidence = digit_tokens / len(words)

        penalty = 0.0
        if own_prev_text:
            own_tokens = _tokens(own_prev_text)
            union = tokens | own_tokens
            if union:
                similarity = len(tokens & own_tokens) / len(union)
                if similarity > 0.8:
                    penalty = similarity * self.repetition_penalty

        score = (
            self.substance_weight * substance
            + self.rebuttal_weight * rebuttal
            + self.evidence_weight * evidence
            - penalty
        )
        return max(0.0, round(score, 6))

    def judge_round(
        self,
        round_no: int,
        arg_a: str,
        arg_b: str,
        prev_a: str | None = None,
        prev_b: str | None = None,
    ) -> RoundVerdict:
        """Score one round: A rebuts B's previous argument and vice versa."""
        score_a = self.score_argument(arg_a, opponent_prev_text=prev_b, own_prev_text=prev_a)
        score_b = self.score_argument(arg_b, opponent_prev_text=prev_a, own_prev_text=prev_b)
        if score_a > score_b:
            winner = DEBATER_A
        elif score_b > score_a:
            winner = DEBATER_B
        else:
            winner = WINNER_TIE
        return RoundVerdict(round_no=round_no, score_a=score_a, score_b=score_b, winner=winner)

    def judge_debate(
        self,
        debate: Debate,
        args_a: Sequence[str],
        args_b: Sequence[str],
    ) -> DebateResult:
        """Run every round and aggregate. Raises on malformed input (fail-closed)."""
        if not isinstance(debate, Debate):
            raise TypeError(f"debate must be a Debate, got {type(debate).__name__}")
        a_list = _check_arg_list(args_a, "args_a")
        b_list = _check_arg_list(args_b, "args_b")
        if len(a_list) != debate.rounds or len(b_list) != debate.rounds:
            raise ValueError(
                f"argument counts ({len(a_list)}, {len(b_list)}) must equal "
                f"debate rounds ({debate.rounds})"
            )

        verdicts: list[RoundVerdict] = []
        prev_a: str | None = None
        prev_b: str | None = None
        total_a = 0.0
        total_b = 0.0
        wins_a = 0
        wins_b = 0
        for i in range(debate.rounds):
            verdict = self.judge_round(i + 1, a_list[i], b_list[i], prev_a, prev_b)
            verdicts.append(verdict)
            total_a += verdict.score_a
            total_b += verdict.score_b
            if verdict.winner == DEBATER_A:
                wins_a += 1
            elif verdict.winner == DEBATER_B:
                wins_b += 1
            prev_a, prev_b = a_list[i], b_list[i]

        # Winner: more round wins; round-win tie broken by total score;
        # exact tie stays a tie (deterministic).
        if wins_a > wins_b:
            winner = DEBATER_A
        elif wins_b > wins_a:
            winner = DEBATER_B
        elif total_a > total_b:
            winner = DEBATER_A
        elif total_b > total_a:
            winner = DEBATER_B
        else:
            winner = WINNER_TIE

        return DebateResult(
            debate_id=debate.debate_id,
            topic=debate.topic,
            rounds=debate.rounds,
            total_a=round(total_a, 6),
            total_b=round(total_b, 6),
            round_wins_a=wins_a,
            round_wins_b=wins_b,
            winner=winner,
            round_verdicts=tuple(verdicts),
        )


def _check_arg_list(value: object, name: str) -> Tuple[str, ...]:
    """Validate a per-side argument list: non-empty sequence of non-empty strs."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"{name} must be a sequence of argument strings, got {type(value).__name__}")
    items = tuple(value)
    if not items:
        raise ValueError(f"{name} must be non-empty")
    for i, item in enumerate(items):
        _check_text(item, f"{name}[{i}]")
    return items


def run_debate(
    topic: str,
    agent_a_args: Sequence[str],
    agent_b_args: Sequence[str],
    debate_id: str = "debate-000001",
    seq: int = 0,
    judge: Judge | None = None,
) -> DebateResult:
    """Run the full debate protocol and return the result.

    ``agent_a_args`` / ``agent_b_args`` are the per-round argument texts for
    each side (index 0 = round 1). Both lists must have the same length; that
    length is the round count. The returned :class:`DebateResult`'s
    ``winner`` field names the winning side (``"a"``, ``"b"``, or ``"tie"``).
    """
    a_list = _check_arg_list(agent_a_args, "agent_a_args")
    b_list = _check_arg_list(agent_b_args, "agent_b_args")
    if len(a_list) != len(b_list):
        raise ValueError(
            f"both sides must argue the same number of rounds, "
            f"got {len(a_list)} vs {len(b_list)}"
        )
    debate = Debate(debate_id=debate_id, topic=topic, rounds=len(a_list), seq=seq)
    active_judge = judge if judge is not None else Judge()
    if not isinstance(active_judge, Judge):
        raise TypeError(f"judge must be a Judge, got {type(active_judge).__name__}")
    return active_judge.judge_debate(debate, a_list, b_list)


def debate_audit_event(result: DebateResult, seq: int) -> dict:
    """Shape a protocol outcome as an audit.ndjson/1-style record."""
    _check_seq(seq, "seq")
    if not isinstance(result, DebateResult):
        raise TypeError(f"result must be a DebateResult, got {type(result).__name__}")
    event = result.as_dict()
    event["audit_seq"] = seq
    return event


def main() -> None:
    a_args = [
        "The policy reduces costs by 15 percent according to the 2024 audit, and the rollout completed in 3 phases.",
        "Your claim about delays ignores the 2025 report: phase 2 finished 2 weeks early, contradicting the delay narrative.",
    ]
    b_args = [
        "Costs are down.",
        "Delays happened.",
    ]
    result = run_debate("Should the policy continue?", a_args, b_args)
    assert result.winner == "a", f"expected side a to win, got {result.winner}"
    assert result.round_wins_a >= result.round_wins_b
    tie = run_debate("X?", ["same text here"], ["same text here"])
    assert tie.winner == "tie", f"expected tie, got {tie.winner}"
    print("debate-protocol OK: substantive side wins, identical sides tie")


if __name__ == "__main__":
    main()
