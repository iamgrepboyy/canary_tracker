"""First- and second-order canary tracker for Burp's legacy Jython API."""

import json
import re
import threading
import uuid
from datetime import datetime

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IParameter
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.lang import Runnable
from java.util import ArrayList
from javax.swing import (
    JCheckBox,
    JButton,
    JLabel,
    JMenuItem,
    JOptionPane,
    JPanel,
    JScrollPane,
    JTable,
    JTextField,
    SwingUtilities,
)
from javax.swing.table import DefaultTableModel


_CANARY_PATTERN = re.compile(r"zx7f3k_[a-f0-9]{10}_\d+")
_SENSITIVE_NAMES = re.compile(
    r"(?i)(^|[_-])(password|passwd|secret|token|access[_-]?token|refresh[_-]?token|"
    r"authorization|csrf|xsrf|nonce|otp|code|session|cookie|signature|sig)([_-]|$)"
)
_MAX_MARKERS = 2000
_MAX_FINDINGS = 5000


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _Runnable(Runnable):
    def __init__(self, callback):
        self.callback = callback

    def run(self):
        self.callback()


class _ReadOnlyModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.lock = threading.RLock()
        self.markers = {}
        self.findings = []
        self.active_context = "default"
        self.inject_enabled = False
        self.scope_only = True
        self._load_state()
        self._build_ui()
        callbacks.setExtensionName("First/Second-Order Canary Tracker")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("First/Second-Order Canary Tracker loaded; injection is disabled by default")

    def getTabCaption(self):
        return "Canary Tracker"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        item = JMenuItem("Set active role/session from selected request")
        item.addActionListener(
            _Action(lambda: self._set_context_from_message(messages[0]))
        )
        items = ArrayList()
        items.add(item)
        return items

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if message_is_request:
            self._inject_into_proxy_request(tool_flag, message_info)
        else:
            self._match_response(message_info)

    def _build_ui(self):
        self.panel = JPanel(BorderLayout(6, 6))
        self.model = _ReadOnlyModel(
            [
                "Finding",
                "Canary",
                "Parameter",
                "Origin",
                "Origin context",
                "Seen at",
                "Observed context",
                "Observed time",
            ],
            0,
        )
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.inject_box = JCheckBox("Inject into eligible Proxy parameters (active scope only)")
        self.inject_box.setSelected(False)
        self.inject_box.addActionListener(_Action(self._update_injection_state))
        self.scope_box = JCheckBox("In-scope only", True)
        self.scope_box.addActionListener(_Action(self._update_scope_state))
        controls.add(self.inject_box)
        controls.add(self.scope_box)
        controls.add(JLabel("Active role/session:"))
        self.context_field = JTextField("default", 14)
        controls.add(self.context_field)
        context_button = JButton("Set context")
        context_button.addActionListener(_Action(self._set_active_context))
        controls.add(context_button)
        clear_button = JButton("Clear findings")
        clear_button.addActionListener(_Action(self._clear_findings))
        controls.add(clear_button)
        self.panel.add(controls, BorderLayout.NORTH)

        self.status_label = JLabel(
            "Injection is off. Cookies and common credential/CSRF parameters are never modified."
        )
        self.panel.add(self.status_label, BorderLayout.SOUTH)
        self._refresh_table()

    def _update_injection_state(self):
        self.inject_enabled = bool(self.inject_box.isSelected())
        if self.inject_enabled:
            self.status_label.setText(
                "Canary injection enabled for eligible Proxy requests%s."
                % (" in scope" if self.scope_only else "")
            )
        else:
            self.status_label.setText("Canary injection disabled; existing markers are still tracked.")

    def _update_scope_state(self):
        self.scope_only = bool(self.scope_box.isSelected())
        self._update_injection_state()

    def _set_active_context(self):
        label = str(self.context_field.getText()).strip()
        self.active_context = label or "default"
        self.context_field.setText(self.active_context)
        self.status_label.setText("Active role/session label: " + self.active_context)

    def _set_context_from_message(self, message_info):
        label = JOptionPane.showInputDialog(
            self.panel,
            "Role/session label for subsequent observed traffic:",
            self.active_context,
        )
        if label is not None:
            self.context_field.setText(str(label))
            self._set_active_context()

    def _clear_findings(self):
        answer = JOptionPane.showConfirmDialog(
            self.panel,
            "Clear all persisted marker origins and findings?",
            "Clear canary data",
            JOptionPane.YES_NO_OPTION,
        )
        if answer != JOptionPane.YES_OPTION:
            return
        with self.lock:
            self.markers = {}
            self.findings = []
            self._save_state_locked()
        self._refresh_table()
        self.status_label.setText("Canary data cleared.")

    def _inject_into_proxy_request(self, tool_flag, message_info):
        if tool_flag != self.callbacks.TOOL_PROXY or not self.inject_enabled:
            return
        try:
            request = message_info.getRequest()
            service = message_info.getHttpService()
            if request is None or service is None:
                return
            request_info = self.helpers.analyzeRequest(service, request)
            request_url = request_info.getUrl()
            if self.scope_only and not self.callbacks.isInScope(request_url):
                return
            if not request_info.getParameters():
                return
            request_text = self.helpers.bytesToString(request)
            if "zx7f3k_" in request_text:
                return

            request_id = uuid.uuid4().hex[:10]
            context = self.active_context
            changed_request = request
            created = []
            parameters = list(request_info.getParameters())
            for index, parameter in enumerate(parameters):
                parameter_type = int(parameter.getType())
                name = str(parameter.getName())
                if not self._eligible_parameter(parameter_type, name):
                    continue
                marker = "zx7f3k_%s_%d" % (request_id, index)
                replacement = self.helpers.buildParameter(
                    name, marker, parameter_type
                )
                changed_request = self.helpers.updateParameter(
                    changed_request, replacement
                )
                created.append(
                    {
                        "marker": marker,
                        "request_id": request_id,
                        "parameter": name,
                        "origin_url": str(request_url),
                        "origin_context": context,
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )

            if not created:
                return
            message_info.setRequest(changed_request)
            with self.lock:
                for entry in created:
                    self.markers[entry["marker"]] = entry
                if len(self.markers) > _MAX_MARKERS:
                    oldest = sorted(
                        self.markers.values(), key=lambda item: item.get("created_at", "")
                    )[: len(self.markers) - _MAX_MARKERS]
                    for entry in oldest:
                        self.markers.pop(entry["marker"], None)
                self._save_state_locked()
            self._set_status_async(
                "Injected %d canary marker(s) into %s parameters."
                % (len(created), str(request_url))
            )
        except Exception as error:
            self.callbacks.printError("Canary injection failed: " + str(error))

    def _eligible_parameter(self, parameter_type, name):
        excluded_types = [IParameter.PARAM_COOKIE]
        allowed_types = [IParameter.PARAM_URL, IParameter.PARAM_BODY]
        for constant_name in ("PARAM_JSON", "PARAM_XML", "PARAM_XML_ATTR", "PARAM_MULTIPART_ATTR"):
            value = getattr(IParameter, constant_name, None)
            if value is not None:
                allowed_types.append(int(value))
        if parameter_type in excluded_types or parameter_type not in allowed_types:
            return False
        if _SENSITIVE_NAMES.search(name):
            return False
        return True

    def _match_response(self, message_info):
        try:
            response = message_info.getResponse()
            request = message_info.getRequest()
            if response is None:
                return
            response_text = self.helpers.bytesToString(response)
            found_markers = set(_CANARY_PATTERN.findall(response_text))
            if not found_markers:
                return
            request_text = self.helpers.bytesToString(request) if request is not None else ""
            seen_url = "unknown"
            if request is not None:
                try:
                    seen_url = str(
                        self.helpers.analyzeRequest(
                            message_info.getHttpService(), request
                        ).getUrl()
                    )
                except Exception:
                    pass
            current_context = self.active_context
            new_findings = []
            with self.lock:
                for marker in found_markers:
                    origin = self.markers.get(marker)
                    if origin is None:
                        continue
                    reflected_in_request = marker in request_text
                    if reflected_in_request:
                        finding_type = "First-order reflection"
                    elif current_context != origin["origin_context"]:
                        finding_type = "Cross-context exposure"
                    else:
                        finding_type = "Second-order resurfacing"
                    finding = {
                        "finding": finding_type,
                        "marker": marker,
                        "parameter": origin.get("parameter", ""),
                        "origin_url": origin.get("origin_url", ""),
                        "origin_context": origin.get("origin_context", "default"),
                        "seen_at": seen_url,
                        "observed_context": current_context,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    if not any(
                        existing["marker"] == marker
                        and existing["seen_at"] == seen_url
                        and existing["observed_context"] == current_context
                        for existing in self.findings[-50:]
                    ):
                        self.findings.append(finding)
                        new_findings.append(finding)
                if len(self.findings) > _MAX_FINDINGS:
                    self.findings = self.findings[-_MAX_FINDINGS:]
                if new_findings:
                    self._save_state_locked()
            if new_findings:
                self._refresh_table_async()
                self._set_status_async(
                    "Found %d canary match(es); newest: %s."
                    % (len(new_findings), new_findings[-1]["finding"])
                )
        except Exception as error:
            self.callbacks.printError("Canary response scan failed: " + str(error))

    def _refresh_table_async(self):
        SwingUtilities.invokeLater(_Runnable(self._refresh_table))

    def _set_status_async(self, message):
        SwingUtilities.invokeLater(
            _Runnable(lambda: self.status_label.setText(message))
        )

    def _refresh_table(self):
        self.model.setRowCount(0)
        with self.lock:
            findings = list(self.findings)
        for finding in reversed(findings):
            self.model.addRow(
                [
                    finding.get("finding", ""),
                    finding.get("marker", ""),
                    finding.get("parameter", ""),
                    finding.get("origin_url", ""),
                    finding.get("origin_context", ""),
                    finding.get("seen_at", ""),
                    finding.get("observed_context", ""),
                    finding.get("timestamp", ""),
                ]
            )

    def _load_state(self):
        try:
            state_text = self.callbacks.loadExtensionSetting("canary_tracker_state_v1")
            if not state_text:
                return
            state = json.loads(state_text)
            self.markers = state.get("markers", {})
            self.findings = state.get("findings", [])[-_MAX_FINDINGS:]
        except Exception as error:
            self.callbacks.printError("Could not load canary data: " + str(error))

    def _save_state_locked(self):
        try:
            state = {"markers": self.markers, "findings": self.findings}
            self.callbacks.saveExtensionSetting(
                "canary_tracker_state_v1", json.dumps(state, ensure_ascii=True)
            )
        except Exception as error:
            self.callbacks.printError("Could not persist canary data: " + str(error))