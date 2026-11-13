# Speaker selection for group chats (round-robin + model-based)

Slice: `B173 autogen-speaker-selector`
Module: `components/northstar-agent-runtime/speaker_selector.py`
Tests: `components/northstar-agent-runtime/tests/test_speaker_selector.py`

## 0. What this document is

Northstar had `multi_agent.py` (a ledger of *declared* agent instances,
coordination rounds and merged outcomes) and `debate.py` /
`debate_protocol.py` (a two-sided argument/judgement protocol), but no
mechanism that answers "**who speaks next** in a group chat". This slice
adds that mechanism, absorbing AutoGen's speaker selection.

Every claim below is marked with one of two labels:

- **[VERBATIM]** — quoted from the source, reproduced character for
  character inside a fenced block, with the source named.
- **[REPO]** — a fact about Northstar's own code, with a file:line
  reference.
- **[EXTENSION]** — a Northstar design decision. AutoGen has no such
  thing; it is *not* presented as AutoGen behaviour.
- **[DEVIATION]** — a deliberate, documented difference from AutoGen.

## 1. Sources (read, not guessed)

1. AutoGen 0.5.5 API docs — `RoundRobinGroupChatManager` source page:
   <https://microsoft.github.io/autogen/0.5.5/_modules/autogen_agentchat/teams/_group_chat/_round_robin_group_chat.html>
2. AutoGen 0.5.5 API docs — `SelectorGroupChatManager` source page:
   <https://microsoft.github.io/autogen/0.5.5/_modules/autogen_agentchat/teams/_group_chat/_selector_group_chat.html>
3. AutoGen 0.4.5 user guide — "Selector Group Chat":
   <https://microsoft.github.io/autogen/0.4.5/_sources/user-guide/agentchat-user-guide/selector-group-chat.ipynb.txt>
4. n4n.ai — "AutoGen SelectorGroupChat: dynamic speaker selection":
   <https://www.n4n.ai/blog/autogen-selectorgroupchat-dynamic-speaker-selection/>

## 2. Round-robin selection

### 2.1 The mechanic

AutoGen's `RoundRobinGroupChatManager` keeps a cursor over the
participant list. Verbatim from source 1:

**[VERBATIM]** (source 1, `RoundRobinGroupChatManager.select_speaker`):

```python
    async def select_speaker(self, thread: List[BaseAgentEvent | BaseChatMessage]) -> str:
        """Select a speaker from the participants in a round-robin fashion."""
        current_speaker_index = self._next_speaker_index
        self._next_speaker_index = (current_speaker_index + 1) % len(self._participant_names)
        current_speaker = self._participant_names[current_speaker_index]
        return current_speaker
```

**[VERBATIM]** (source 1, the cursor's initial value):

```python
        self._next_speaker_index = 0
```

**[VERBATIM]** (source 1, `save_state` / `load_state`):

```python
    async def save_state(self) -> Mapping[str, Any]:
        state = RoundRobinManagerState(
            message_thread=[message.dump() for message in self._message_thread],
            current_turn=self._current_turn,
            next_speaker_index=self._next_speaker_index,
        )
        return state.model_dump()
```

**[VERBATIM]** (source 1, `reset`):

```python
    async def reset(self) -> None:
        self._current_turn = 0
        self._message_thread.clear()
        if self._termination_condition is not None:
            await self._termination_condition.reset()
        self._next_speaker_index = 0
```

Facts taken from that text:

- the cursor is initialised at `0`;
- the selected participant is the one at the *current* index, and the
  cursor is advanced by `(current + 1) % len(participants)` — so the
  rotation is strictly modulo the participant count;
- the cursor is part of the saved state, so a resumed chat continues
  from the same position in the rotation;
- `reset()` returns the cursor to `0`.

**[REPO]** Northstar has no such cursor today:
`components/northstar-agent-runtime/multi_agent.py:536` (`coordinate`)
takes a participant set and sorts it (`multi_agent.py:275`,
`_check_participants` returns `tuple(sorted(ids))`), but no member of the
ledger ever picks a speaker — the caller declares the round's
participants. `components/northstar-agent-runtime/debate.py` and
`debate_protocol.py` fix the order of the *argument* phase
(`debate_protocol.py:89`, `class Debate`, declares `side_a`/`side_b`),
so the two sides are structurally fixed, not selected.

### 2.2 Northstar implementation

`RoundRobinSelector` keeps the same mechanic with a plain dict for the
state:

- `next_speaker_index` starts at `0`;
- `select_speaker()` returns the participant at the current index and
  advances the cursor by `(index + 1) % len(participants)`;
- with a single participant the modulo is `1`, so the cursor never
  moves and the same participant is always the speaker;
- `state()` / `restore()` carry the index, so a resumed chat does not
  slip a position in the rotation.

**[EXTENSION]** The state is a plain JSON-compatible dict rather than
AutoGen's pydantic `RoundRobinManagerState`, and Northstar carries only
the cursor (not the message thread) — the transcript lives in the host.

## 3. Model-based selection

### 3.1 What the selector model sees

**[VERBATIM]** (source 3, "How Does it Work?"):

```
1. The team analyzes the current conversation context, including the conversation history and participants' {py:attr}`~autogen_agentchat.base.ChatAgent.name` and {py:attr}`~autogen_agentchat.base.ChatAgent.description` attributes, to determine the next speaker using a model. By default, the team will not select the same speak consecutively unless it is the only agent available. This can be changed by setting `allow_repeated_speaker=True`. You can also override the model by providing a custom selection function.
```

**[VERBATIM]** (source 4, the prompt shape):

```python
selector_prompt = """You are a conversation router.
Given the transcript, pick the single agent best suited for the next turn.
Respond with exactly one of: Planner, Coder, Critic.
Do not explain your choice."""
```

**[VERBATIM]** (source 4, on parsing and fallback):

> The model is expected to return **only** a valid participant name. AutoGen parses the response, strips whitespace, and checks membership. If the output is ambiguous or invalid, the team falls back to the previous speaker or a random pick depending on version—never silently hangs.

**[VERBATIM]** (source 4, on why it is not round-robin):

> **"It's just round-robin with an LLM wrapper."**
> No. Round-robin is deterministic and ignores content. SelectorGroupChat's output varies with every transcript. The LLM is making a fresh decision each turn.

**[VERBATIM]** (source 4, on the cost):

> **"Selection is free."**
> Each turn adds one inference call. With `gpt-4o` as the router on a 10-agent chat, that's noticeable latency and cost. Use a small model (`gpt-4o-mini` or equivalent) for the `model_client` dedicated to selection; agent answers can use a stronger model.

**[VERBATIM]** (source 4, on the round-robin cost):

> After the Planner speaks, the Coder should almost always go next. After the Coder returns a traceback, the Critic may flag it and hand back to Coder. A round-robin would force Critic to speak even when nothing needs reviewing, polluting context and burning tokens.

### 3.2 The output contract in AutoGen's code

**[VERBATIM]** (source 2, `SelectorGroupChatManager._select_speaker`, the
three rejection branches):

```python
            mentions = self._mentioned_agents(response.content, self._participant_names)
            if len(mentions) == 0:
                trace_logger.debug(f"Model failed to select a valid name: {response.content} (attempt {num_attempts})")
                feedback = f"No valid name was mentioned. Please select from: {str(participants)}."
                select_speaker_messages.append(UserMessage(content=feedback, source="user"))
            elif len(mentions) > 1:
                trace_logger.debug(f"Model selected multiple names: {str(mentions)} (attempt {num_attempts})")
                feedback = (
                    f"Expected exactly one name to be mentioned. Please select only one from: {str(participants)}."
                )
                select_speaker_messages.append(UserMessage(content=feedback, source="user"))
            else:
                agent_name = list(mentions.keys())[0]
                if (
                    not self._allow_repeated_speaker
                    and self._previous_speaker is not None
                    and agent_name == self._previous_speaker
                ):
                    trace_logger.debug(f"Model selected the previous speaker: {agent_name} (attempt {num_attempts})")
                    feedback = (
                        f"Repeated speaker is not allowed, please select a different name from: {str(participants)}."
                    )
                    select_speaker_messages.append(UserMessage(content=feedback, source="user"))
                else:
                    # Valid selection
                    trace_logger.debug(f"Model selected a valid name: {agent_name} (attempt {num_attempts})")
                    return agent_name
```

**[VERBATIM]** (source 2, the last-resort fallback):

```python
        if self._previous_speaker is not None:
            trace_logger.warning(f"Model failed to select a speaker after {max_attempts}, using the previous speaker.")
            return self._previous_speaker
        trace_logger.warning(
            f"Model failed to select a speaker after {max_attempts} and there was no previous speaker, using the first participant."
        )
        return participants[0]
```

**[VERBATIM]** (source 2, the candidate set that excludes the previous
speaker):

```python
            if self._previous_speaker is not None and not self._allow_repeated_speaker:
                participants = [p for p in self._participant_names if p != self._previous_speaker]
            else:
                participants = list(self._participant_names)
```

**[VERBATIM]** (source 2, the single-candidate short-circuit):

```python
        if len(participants) > 1:
            agent_name = await self._select_speaker(roles, participants, history, self._max_selector_attempts)
        else:
            agent_name = participants[0]
```

**[VERBATIM]** (source 2, `max_selector_attempts` default):

```python
        max_selector_attempts: int = 3,
```

### 3.3 Northstar implementation

`ModelSelector` implements the same contract, but the model call is
**injected by the caller**:

```python
selector = ModelSelector(
    [Participant("Planner", "..."), Participant("Coder", "...")],
    model=lambda request: "Coder",
)
```

**[EXTENSION]** `speaker_selector.py` never calls a model. The caller
passes a callable that receives a `SelectionRequest` (transcript,
roster, eligible candidates, previous speaker, optional retry feedback)
and returns the raw model text. AutoGen owns a model client inside the
team; Northstar keeps the host in charge of every provider call.

Resolution order in `ModelSelector.select_speaker`:

1. **`selector_func`** (custom rule) — when it returns a name. A name
   that is not a participant is unusable and falls back. `None` defers
   to the model, exactly like AutoGen's contract.
2. **the injected model** — the reply is stripped and matched against
   the roster. Zero mentions (blank, unknown name), or more than one
   mention (ambiguous) are unusable replies and are retried up to
   `max_attempts` (default 3, AutoGen's default) with a feedback
   message, then fall back.
3. **the fallback** — never a hang: every path ends in a concrete
   participant name.

Fallback modes:

- `FALLBACK_PREVIOUS` (default) — the previous speaker keeps the
  floor, matching AutoGen's last-resort branch. With no previous
  speaker yet, the first participant takes it (AutoGen's second
  branch).
- `FALLBACK_RANDOM` — a random eligible participant. This is the
  "random pick" variant the n4n.ai text mentions as version-dependent.

`parse_selection()` mirrors AutoGen's `_mentioned_agents` counting: the
reply is stripped, every roster name appearing in it is counted, and
only exactly one mention yields a name.

### 3.4 The no-repeat rule

AutoGen keeps two things apart: the *candidate set* excludes the
previous speaker, while the *last-resort fallback* may still return the
previous speaker (source 2, quoted above). The two can therefore
contradict each other on the fallback path.

**[DEVIATION]** Northstar keeps the two paths apart explicitly:

- an **illegal reply** (no mention, several mentions, a non-member) →
  the fallback lands on the **previous speaker** (AutoGen's behaviour);
- a reply that names a **member who is only ineligible because of the
  no-repeat rule** → the fallback lands on an **eligible** participant.

With that split the invariant "the same speaker is never selected twice
in a row" holds on every path while `allow_repeated_speaker` is false,
and the AutoGen-compatible "previous speaker keeps the floor" behaviour
is preserved for the genuinely broken reply.

`allow_repeated_speaker=True` disables the exclusion entirely
(AutoGen's `allow_repeated_speaker=True`, source 3), and when only one
participant exists it is always the speaker (source 2, the
single-candidate short-circuit).

## 4. The selection record (Northstar extension)

**[EXTENSION]** AutoGen keeps no ledger of who was selected. Northstar
books one `SelectionRecord` per round:

| field | meaning |
|---|---|
| `round_index` | 0-based index of the round |
| `speaker` | the selected participant's name |
| `rule` | `round-robin` / `model` / `custom` / `fallback` |
| `fallback` | True when the speaker was *not* produced by the primary rule |
| `transcript_digest` | `sha256:` pin of the transcript the decision was made against |
| `reason` | short human-readable justification |
| `digest` | pin of the record itself, checkable with `verify()` |

The `rule` vocabulary is pinned (`speaker_selector.py`, `RULE_ROUND_ROBIN`,
`RULE_MODEL`, `RULE_CUSTOM`, `RULE_FALLBACK`); a record carrying an
unknown rule is refused (`BadRuleError`).

The `transcript_digest` follows the Northstar house rule that raw text
does not cross an audit boundary: the transcript travels to the record
as a digest pin only, never as bytes. This mirrors `multi_agent.py`,
where the task and outcome travel as `sha256:` pins
(`multi_agent.py:280`, `_pin_bytes`; `multi_agent.py:298`, `_digest_of`).

## 5. Termination guard

**[EXTENSION]** AutoGen's teams take a termination *condition*
(`MaxMessageTermination`, `TextMentionTermination` in source 3). Northstar's
driver takes a hard round budget instead:

```python
chat = SpeakerGroupChat(selector, max_rounds=8)
records = chat.run(lambda name: f"{name}: done")
```

`run()` stops at the budget; `select_next()` raises `MaxRoundsError`
once the budget is spent. The chat never rotates forever.

## 6. Integration points with Northstar's own modules

**[EXTENSION]** The integration is *defined here*; AutoGen has no
equivalent.

- `multi_agent.py` books a **declared** coordination round with a
  participant set (`multi_agent.py:536`). A `SpeakerGroupChat` over the
  same participant set produces the *order* of those participants; the
  two are complementary — the ledger declares who may speak, the
  selector decides who speaks next. `MultiAgent.coordinate()` requires
  every participant to be spawned (`multi_agent.py:547`), so a Northstar
  host would spawn the roster first and then feed the same names to the
  selector.
- `debate.py` / `debate_protocol.py` fix the two sides structurally
  (`debate_protocol.py:89`). The selector does not replace that: it is
  for *group* chats, where the number of speakers is not fixed in
  advance.

## 7. What this module does NOT do

- It does not call a model. The model call is injected.
- It does not run agents, tools or a transcript of its own; the host
  owns the agent loop and feeds the transcript in.
- It does not prove that the selected speaker actually produced a
  reply — like `multi_agent.py`'s merge record, a `SelectionRecord`
  proves that a *decision was booked*, not that an agent obeyed it.
- It is not AutoGen code and does not claim AutoGen's guarantees.

## 8. Test map

| acceptance rule | test |
|---|---|
| round-robin order follows index modulo | `test_round_robin_order_follows_index_modulo` |
| single participant is the sole speaker | `test_round_robin_single_participant_is_sole_speaker` |
| state restore keeps the index aligned | `test_round_robin_state_restore_keeps_index` |
| model reply with a legal name is selected | `test_model_legal_name_is_selected_and_recorded` |
| selection follows the transcript, not a fixed order | `test_model_selection_follows_transcript_not_order` |
| illegal reply falls back to the previous speaker | `test_model_illegal_name_falls_back_to_previous` |
| blank reply falls back | `test_model_blank_reply_falls_back` |
| ambiguous (multiple names) reply falls back | `test_model_multiple_names_falls_back` |
| random fallback mode | `test_model_fallback_random_mode` |
| never hangs on an unusable reply | `test_model_never_hangs_on_unusable_reply` |
| model exception is contained | `test_model_exception_is_contained` |
| reply parsing is strict about ambiguity | `test_parse_selection_is_strict_about_ambiguity` |
| no-repeat by default | `test_no_repeat_excludes_previous_by_default` |
| no-repeat only when one agent is available | `test_no_repeat_only_when_one_agent_is_available` |
| `allow_repeated_speaker=True` permits repeats | `test_allow_repeated_speaker_permits_repeats` |
| candidate set excludes the previous speaker | `test_no_repeat_candidates_exclude_previous` |
| custom selection function overrides the model | `test_custom_selector_func_overrides_model` |
| custom function returning `None` defers to the model | `test_custom_selector_func_none_defers_to_model` |
| custom function returning a non-member falls back | `test_custom_selector_func_returning_non_member_falls_back` |
| custom function raising falls back | `test_custom_selector_func_raising_falls_back` |
| `max_rounds` guard stops the chat | `test_max_rounds_guard_stops_the_chat` |
| the guard bounds an unbounded loop | `test_max_rounds_guard_bounds_an_unbounded_loop` |
| selection record fields are complete | `test_selection_record_fields_are_complete` |
| the record pin detects tampering | `test_record_pin_detects_tampering` |
| roster validation refuses bad rosters | `test_participant_validation_refuses_bad_rosters` |
| name-length boundary | `test_participant_name_length_boundary` |
| version / schema pins | `test_version_and_schema_pins` |
| real path (a): round-robin trio | `test_real_path_round_robin_trio` |
| real path (b): model selector content-driven | `test_real_path_model_selector_content_driven` |
| real path (c): no-repeat rule | `test_real_path_no_repeat_rule` |
| fallback never hangs | `test_real_path_fallback_never_hangs` |
| driver state round trip keeps the rotation | `test_driver_state_round_trip_keeps_rotation` |
| the selection request exposes roster and transcript | `test_selection_request_exposes_roster_and_transcript` |
| the previous speaker rides with the state | `test_model_state_restore_keeps_previous_speaker` |
| a restored state rejects an unknown speaker | `test_model_state_restore_rejects_unknown_speaker` |
