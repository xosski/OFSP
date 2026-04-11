"""Smoke tests that validate Orbital Station tab and button interactions."""

import os
import unittest

from PySide6.QtWidgets import QApplication, QPushButton

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("ORBITAL_UI_SKIP_BACKEND_INIT", "1")

from OrbitalStationUI_Complete import OrbitalStationUI


class OrbitalStationInteractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.ui = OrbitalStationUI()

    def tearDown(self):
        self.ui.close()

    def test_all_tabs_are_reachable(self):
        tabs = self.ui.tabs
        self.assertGreater(tabs.count(), 0, "Expected at least one tab")

        for index in range(tabs.count()):
            tabs.setCurrentIndex(index)
            self.assertEqual(
                tabs.currentIndex(),
                index,
                f"Failed to switch to tab index {index}: {tabs.tabText(index)}",
            )

    def test_critical_buttons_have_click_handlers(self):
        critical_buttons = [
            self.ui.quick_scan_btn,
            self.ui.deep_scan_btn,
            self.ui.stop_scan_btn,
            self.ui.enable_protection_btn,
            self.ui.disable_protection_btn,
            self.ui.quarantine_btn,
            self.ui.restore_btn,
            self.ui.delete_btn,
            self.ui.fs_quick_scan_btn,
            self.ui.fs_full_scan_btn,
            self.ui.fs_custom_scan_btn,
            self.ui.fs_browser_scan_btn,
            self.ui.fs_stop_scan_btn,
            self.ui.start_memory_scan_btn,
            self.ui.start_process_scan_btn,
            self.ui.start_deep_scan_btn,
        ]

        for button in critical_buttons:
            self.assertGreater(
                button.receivers("2clicked()"),
                0,
                f"Expected a click handler for button: {button.text()}",
            )

    def test_filetype_filter_buttons_stay_consistent(self):
        self.ui.scan_all_files.click()
        self.assertTrue(self.ui.scan_all_files.isChecked())
        self.assertFalse(self.ui.scan_executables.isChecked())
        self.assertFalse(self.ui.scan_scripts.isChecked())
        self.assertFalse(self.ui.scan_documents.isChecked())

        self.ui.scan_scripts.click()
        self.assertTrue(self.ui.scan_scripts.isChecked())
        self.assertFalse(self.ui.scan_all_files.isChecked())


if __name__ == "__main__":
    unittest.main()
