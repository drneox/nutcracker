"""Tests de nutcracker_core/plugins/dashboard/chat_mailbox.py (Fase 3, wiring
del chat operador→agente aipwn)."""

from __future__ import annotations

from nutcracker_core.plugins.dashboard import chat_mailbox


def setup_function():
    chat_mailbox._pending.clear()


def test_drain_empty_package_returns_empty_list():
    assert chat_mailbox.drain("com.example.app") == []


def test_add_then_drain_returns_messages_in_order():
    chat_mailbox.add("com.example.app", "primero")
    chat_mailbox.add("com.example.app", "segundo")
    assert chat_mailbox.drain("com.example.app") == ["primero", "segundo"]


def test_drain_consumes_messages_only_once():
    chat_mailbox.add("com.example.app", "mensaje único")
    assert chat_mailbox.drain("com.example.app") == ["mensaje único"]
    assert chat_mailbox.drain("com.example.app") == []


def test_packages_are_isolated():
    chat_mailbox.add("com.example.a", "para A")
    chat_mailbox.add("com.example.b", "para B")
    assert chat_mailbox.drain("com.example.a") == ["para A"]
    assert chat_mailbox.drain("com.example.b") == ["para B"]
