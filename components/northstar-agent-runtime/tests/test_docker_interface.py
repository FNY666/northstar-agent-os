"""Tests for docker_interface.py."""

import threading
import unittest

from docker_interface import (
    DOCKER_INTERFACE_VERSION,
    SCHEMA_PIN,
    DockerError,
    DockerInterface,
    DuplicateImageError,
    IllegalTransitionError,
    UnknownContainerError,
    UnknownImageError,
    docker_interface_audit_event,
)


class TestDockerInterface(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(DOCKER_INTERFACE_VERSION, "docker-interface.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.docker-interface.v1")

    def test_build_happy_path(self):
        di = DockerInterface()
        rec = di.build("app", "v1", seq=1, layers=["base"])
        self.assertEqual(rec.name, "app")
        self.assertEqual(rec.tag, "v1")
        self.assertTrue(rec.image_id.startswith("sha256:"))
        self.assertEqual(rec.version, DOCKER_INTERFACE_VERSION)

    def test_build_digest_determinism(self):
        a = DockerInterface().build("app", "v1", seq=1, layers=["x", "y"])
        b = DockerInterface().build("app", "v1", seq=1, layers=["x", "y"])
        self.assertEqual(a.image_id, b.image_id)

    def test_build_recipe_change_refused(self):
        di = DockerInterface()
        di.build("app", "v1", seq=1, layers=["base"])
        with self.assertRaises(DuplicateImageError):
            di.build("app", "v1", seq=2, layers=["evil"])

    def test_build_same_recipe_idempotent(self):
        di = DockerInterface()
        first = di.build("app", "v1", seq=1)
        second = di.build("app", "v1", seq=2)
        self.assertEqual(first.image_id, second.image_id)
        self.assertEqual(len(di.images()), 1)

    def test_run_stop_remove_lifecycle(self):
        di = DockerInterface()
        img = di.build("app", "v1", seq=1)
        start = di.run(img.image_id, seq=2)
        self.assertEqual(start.new_state, "running")
        self.assertEqual(start.previous_state, "absent")
        self.assertEqual(di.container(start.container_id).state, "running")
        stop = di.stop(start.container_id, seq=3)
        self.assertEqual(stop.previous_state, "running")
        self.assertEqual(di.container(start.container_id).state, "stopped")
        self.assertEqual(di.remove(start.container_id, seq=4), start.container_id)
        with self.assertRaises(UnknownContainerError):
            di.container(start.container_id)

    def test_run_unknown_image_refused(self):
        di = DockerInterface()
        with self.assertRaises(UnknownImageError):
            di.run("sha256:nope", seq=1)

    def test_double_stop_refused(self):
        di = DockerInterface()
        img = di.build("app", "v1", seq=1)
        start = di.run(img.image_id, seq=2)
        di.stop(start.container_id, seq=3)
        with self.assertRaises(IllegalTransitionError):
            di.stop(start.container_id, seq=4)

    def test_remove_running_refused(self):
        di = DockerInterface()
        img = di.build("app", "v1", seq=1)
        start = di.run(img.image_id, seq=2)
        with self.assertRaises(IllegalTransitionError):
            di.remove(start.container_id, seq=3)
        # stop then remove works
        di.stop(start.container_id, seq=4)
        di.remove(start.container_id, seq=5)

    def test_stop_unknown_container_refused(self):
        di = DockerInterface()
        with self.assertRaises(UnknownContainerError):
            di.stop("c-999", seq=1)

    def test_bad_inputs_refused(self):
        di = DockerInterface()
        with self.assertRaises(DockerError):
            di.build("", "v1", seq=1)
        with self.assertRaises(DockerError):
            di.build("app", "", seq=1)
        with self.assertRaises(DockerError):
            di.build("app", "v1", seq=-1)
        with self.assertRaises(DockerError):
            di.build("app", "v1", seq=True)

    def test_seq_must_increase(self):
        di = DockerInterface()
        di.build("app", "v1", seq=5)
        with self.assertRaises(DockerError):
            di.build("other", "v1", seq=5)

    def test_containers_state_filter(self):
        di = DockerInterface()
        img = di.build("app", "v1", seq=1)
        a = di.run(img.image_id, seq=2)
        b = di.run(img.image_id, seq=3)
        di.stop(a.container_id, seq=4)
        running = di.containers(state="running")
        stopped = di.containers(state="stopped")
        self.assertEqual([c.container_id for c in running], [b.container_id])
        self.assertEqual([c.container_id for c in stopped], [a.container_id])
        with self.assertRaises(DockerError):
            di.containers(state="exploded")

    def test_audit_event_shapes(self):
        ev = docker_interface_audit_event("container-run", 1, container_id="c-1")
        self.assertEqual(ev["kind"], "audit.ndjson/1")
        self.assertEqual(ev["module"], "docker-interface")
        self.assertEqual(ev["event"], "container-run")
        self.assertEqual(ev["fields"]["container_id"], "c-1")
        with self.assertRaises(DockerError):
            docker_interface_audit_event("pwned", 1)
        with self.assertRaises(DockerError):
            docker_interface_audit_event("image-built", -1)

    def test_thread_safety(self):
        di = DockerInterface()
        img = di.build("app", "v1", seq=0)
        results = []

        def worker(i):
            rec = di.run(img.image_id, seq=1 + i)
            results.append(rec.container_id)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(results)), 10)  # distinct ids


if __name__ == "__main__":
    unittest.main()
