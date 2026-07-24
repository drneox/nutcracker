"""Tests del EventBus del dashboard (Fase 3 del plan)."""

from __future__ import annotations

import queue

import pytest

from nutcracker_core.plugins.dashboard.events import EventBus


def test_publish_without_subscribers_does_not_raise():
    bus = EventBus()
    bus.publish("job-1", "log", "hola")  # no debe lanzar aunque no haya suscriptores


def test_subscriber_receives_published_event():
    bus = EventBus()
    q = bus.subscribe("job-1")
    bus.publish("job-1", "log", "línea 1")
    event = q.get(timeout=1)
    assert event.channel == "job-1"
    assert event.kind == "log"
    assert event.data == "línea 1"


def test_subscribers_on_different_channels_are_isolated():
    bus = EventBus()
    q1 = bus.subscribe("job-1")
    q2 = bus.subscribe("job-2")
    bus.publish("job-1", "log", "solo para job-1")
    assert q1.get(timeout=1).data == "solo para job-1"
    with pytest.raises(queue.Empty):
        q2.get(timeout=0.2)


def test_history_replays_past_events_to_new_subscribers():
    bus = EventBus()
    bus.publish("job-1", "log", "antes de suscribirse")
    hist = bus.history("job-1")
    assert len(hist) == 1
    assert hist[0].data == "antes de suscribirse"


def test_history_size_is_capped():
    bus = EventBus(history_size=3)
    for i in range(10):
        bus.publish("job-1", "log", str(i))
    hist = bus.history("job-1")
    assert len(hist) == 3
    assert [e.data for e in hist] == ["7", "8", "9"]


def test_unsubscribe_stops_delivery():
    bus = EventBus()
    q = bus.subscribe("job-1")
    bus.unsubscribe("job-1", q)
    bus.publish("job-1", "log", "no debería llegar")
    assert q.empty()
