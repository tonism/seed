#!/usr/bin/env python3
"""A visual review may explain an observer miss, never a runtime failure."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('case_gate', HERE/'check_live_h2_case.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class NativeReview(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name)
        # Pixel semantics are reviewed separately; this fixture tests binding.
        (self.case/'answer.png').write_bytes(b'reviewed screenshot fixture')
        digest = hashlib.sha256((self.case/'answer.png').read_bytes()).hexdigest()
        self.binding = dict(native_program=True, case_scope='main')
        self.result = dict(answer=False, error='KeyboardInterrupt()', turns=[True])
        self.events = [dict(event='submitted', turn=1, utc_epoch=1),
                       dict(event='answer', turn=1, ready=True, utc_epoch=2),
                       dict(event='submitted', turn=2, utc_epoch=100),
                       dict(event='controller_error', utc_epoch=2600)]
        self.manual = dict(turn=2, ready=True, input_prompt_returned=True,
                           semantic_ax_decimal=42, semantic_bytes='B8 2A 00 CB',
                           visible_response='AX 42; bytes B8 2A 00 CB',
                           numeric_format_followed=True, review_kind='ocr-omission',
                           utc_epoch=200, screenshot='answer.png', screenshot_sha256=digest)
        self.observation = dict(screenshot='answer.png', screenshot_sha256=digest,
                                expected='42', missing=['42'], engine='tesseract',
                                lines=['prompt echo', '>_'], visual_prompt=True,
                                ocr_prompt=True, observed_utc_epoch=201)

    def validate(self):
        (self.case/'manual-completion.json').write_text(json.dumps(self.manual))
        (self.case/'ocr-observation.json').write_text(json.dumps(self.observation))
        return gate.reviewed_native_completion(self.case, self.binding, self.result, self.events)

    def test_review_kinds_remain_distinct(self):
        self.assertTrue(self.validate()['numeric_format_followed'])
        self.manual.pop('review_kind')
        self.manual.update(numeric_format_followed=False, visible_response='forty-two')
        self.assertFalse(self.validate()['numeric_format_followed'])

    def test_runtime_error_and_incomplete_prior_turn_refuse(self):
        for changes in [dict(error='RuntimeError()'), dict(error=None),
                        dict(answer=True), dict(turns=[False])]:
            with self.subTest(changes=changes):
                saved = copy.deepcopy(self.result)
                self.result.update(changes)
                with self.assertRaises(AssertionError): self.validate()
                self.result = saved

    def test_false_or_unbound_review_refuses(self):
        for changes in [dict(ready=False), dict(input_prompt_returned=False),
                        dict(semantic_ax_decimal=43), dict(semantic_bytes='00'),
                        dict(screenshot_sha256='bad'), dict(screenshot='../answer.png'),
                        dict(review_kind='unknown'), dict(numeric_format_followed=False),
                        dict(utc_epoch=99), dict(utc_epoch=2601)]:
            with self.subTest(changes=changes):
                saved = copy.deepcopy(self.manual)
                self.manual.update(changes)
                with self.assertRaises(AssertionError): self.validate()
                self.manual = saved

    def test_ocr_claim_needs_bound_missing_text_and_prompt(self):
        for changes in [dict(screenshot_sha256='bad'), dict(expected='wrong'),
                        dict(missing=[]), dict(lines=['AX 42', '>_']),
                        dict(visual_prompt=False), dict(ocr_prompt=False),
                        dict(observed_utc_epoch=199), dict(observed_utc_epoch=2601)]:
            with self.subTest(changes=changes):
                saved = copy.deepcopy(self.observation)
                self.observation.update(changes)
                with self.assertRaises(AssertionError): self.validate()
                self.observation = saved

    def test_late_completion_refuses_even_before_observer_stop(self):
        self.manual['utc_epoch'] = 2501
        self.observation['observed_utc_epoch'] = 2502
        with self.assertRaises(AssertionError): self.validate()


if __name__ == '__main__':
    unittest.main()
