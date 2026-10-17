import unittest
from unittest.mock import Mock, patch
from native_window_layout import TestWindowPlacement, corner_position, FLAGS


class WindowLayoutTests(unittest.TestCase):
    def test_four_corners_preserve_size_and_taskbar_workarea(self):
        work, size = (40, 20, 2560, 1400), (1116, 739)
        self.assertEqual([corner_position(n, work, size) for n in (1, 2, 3, 4)],
                         [(40, 20), (1444, 20), (40, 661), (1444, 661)])
        self.assertEqual(corner_position(4, (0, 0, 1024, 768), (1116, 739)), (0, 29))
        with self.assertRaises(ValueError): corner_position(5, work, size)

    def placement(self):
        item = object.__new__(TestWindowPlacement)
        item.pid, item.slot = 42, 4
        item.viewport, item.ready_window = (1100, 700), None
        item.next_poll, item.done, item.request, item.until = 0, False, None, 120
        item.callback_type = lambda fn: fn
        item.api = Mock()
        item.api.SetThreadDpiAwarenessContext.return_value = 1
        item.api.IsWindowVisible.return_value = True
        item.api.GetWindow.return_value = 0
        item.api.GetWindowThreadProcessId.side_effect = lambda window, pid: setattr(pid._obj, 'value', 42 if window == 101 else 99)
        def enumerate_windows(callback, unused):
            callback(100, 0)  # An unrelated process must remain untouched.
            callback(101, 0)
            return True
        item.api.EnumWindows.side_effect = enumerate_windows
        position = [50, 60]
        def rectangle(window, rect):
            rect._obj.left, rect._obj.top = position
            rect._obj.right, rect._obj.bottom = position[0]+1116, position[1]+739
            return True
        def workarea(action, unused, rect, flags):
            self.assertEqual(action, 0x30)
            rect._obj.left, rect._obj.top, rect._obj.right, rect._obj.bottom = 40, 20, 2560, 1400
            return True
        def client_rectangle(window, rect):
            rect._obj.left = rect._obj.top = 0
            rect._obj.right, rect._obj.bottom = item.viewport
            return True
        item.api.GetClientRect.side_effect = client_rectangle
        item.api.GetWindowRect.side_effect = rectangle
        item.api.SystemParametersInfoW.side_effect = workarea
        item.api.SetWindowPos.return_value = True
        return item, position

    def test_owned_window_moves_without_focus_resize_or_debugger_blocking(self):
        item, position = self.placement()
        with patch('native_window_layout.time.monotonic', side_effect=[1, 2, 3, 4]):
            self.assertIsNone(item.poll())
            item.api.SetWindowPos.assert_not_called()  # Wait for stable configured client size.
            self.assertIsNone(item.poll())
            item.api.SetWindowPos.assert_called_once_with(101, None, 1444, 661, 0, 0, 0x4015)
            self.assertEqual(FLAGS, 0x4015)
            self.assertFalse(item.done)  # Asynchronous success is not placement confirmation.
            position[:] = [1444, 661]
            placed = item.poll()
            self.assertEqual(placed, dict(player=4, pid=42, position=(1444, 661), outer_size=(1116, 739)))
            self.assertIsNone(item.poll())
            self.assertEqual(item.api.SetWindowPos.call_count, 1)

    def test_temporary_viewport_waits_and_changed_target_reissues_request(self):
        item, position = self.placement()
        normal = item.api.GetClientRect.side_effect
        def splash(window, rect):
            normal(window, rect)
            rect._obj.right = 640
            return True
        item.api.GetClientRect.side_effect = splash
        with patch('native_window_layout.time.monotonic', side_effect=[1, 2, 3, 4]):
            self.assertIsNone(item.poll())
            item.api.SetWindowPos.assert_not_called()
            item.api.GetClientRect.side_effect = normal
            self.assertIsNone(item.poll())
            self.assertIsNone(item.poll())
            item.request = (101, (100, 100), (1116, 739))
            self.assertIsNone(item.poll())
            self.assertEqual(item.api.SetWindowPos.call_count, 2)

    def test_owned_startup_auxiliary_window_is_filtered_by_viewport(self):
        item, _ = self.placement()
        item.api.GetWindowThreadProcessId.side_effect = lambda window, pid: setattr(pid._obj, 'value', 42)
        normal = item.api.GetClientRect.side_effect
        def sizes(window, rect):
            normal(window, rect)
            if window == 100:
                rect._obj.right, rect._obj.bottom = 640, 480
            return True
        item.api.GetClientRect.side_effect = sizes
        with patch('native_window_layout.time.monotonic', side_effect=[1, 2]):
            self.assertIsNone(item.poll())
            self.assertIsNone(item.poll())
        item.api.SetWindowPos.assert_called_once_with(101, None, 1444, 661, 0, 0, FLAGS)

    def test_identical_viewport_ambiguity_waits_then_times_out_without_moving(self):
        item, _ = self.placement()
        item.api.GetWindowThreadProcessId.side_effect = lambda window, pid: setattr(pid._obj, 'value', 42)
        with patch('native_window_layout.time.monotonic', side_effect=[1, 2, 121]):
            self.assertIsNone(item.poll())
            self.assertIsNone(item.poll())
            with self.assertRaisesRegex(TimeoutError, 'ambiguous configured viewport windows: 2'):
                item.poll()
        item.api.SetWindowPos.assert_not_called()
        self.assertEqual(item.api.SetThreadDpiAwarenessContext.call_args.args, (1,))

    def test_transient_identical_viewport_ambiguity_requires_stable_unique_window(self):
        item, _ = self.placement()
        normal = item.api.GetWindowThreadProcessId.side_effect
        item.api.GetWindowThreadProcessId.side_effect = lambda window, pid: setattr(pid._obj, 'value', 42)
        with patch('native_window_layout.time.monotonic', side_effect=[1, 2, 3]):
            self.assertIsNone(item.poll())
            item.api.GetWindowThreadProcessId.side_effect = normal
            self.assertIsNone(item.poll())
            item.api.SetWindowPos.assert_not_called()
            self.assertIsNone(item.poll())
        item.api.SetWindowPos.assert_called_once_with(101, None, 1444, 661, 0, 0, FLAGS)
