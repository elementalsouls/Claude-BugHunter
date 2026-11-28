import json
import os
import tempfile
import unittest

from scope import Scope


class ScopeFieldTypeTests(unittest.TestCase):
    def test_string_out_of_scope_rejected(self):
        # A str is iterated char by char, so the deny list would silently fail open.
        with self.assertRaises(ValueError):
            Scope(['*.example.com'], 'admin.example.com')

    def test_string_in_scope_rejected(self):
        with self.assertRaises(ValueError):
            Scope('*.example.com')

    def test_string_seeds_rejected(self):
        with self.assertRaises(ValueError):
            Scope(['*.example.com'], seeds='https://example.com/')

    def test_non_string_item_rejected(self):
        with self.assertRaises(ValueError):
            Scope(['*.example.com', 5])

    def test_load_rejects_string_out_of_scope(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'scope.json')
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({'in_scope': ['*.example.com'],
                           'out_of_scope': 'admin.example.com'}, f)
            with self.assertRaises(ValueError):
                Scope.load(path)

    def test_list_form_still_denies(self):
        s = Scope(['*.example.com'], ['admin.example.com'])
        self.assertFalse(s.in_scope_host('admin.example.com'))
        self.assertTrue(s.in_scope_host('www.example.com'))

    def test_none_and_empty_still_work(self):
        s = Scope(['*.example.com'], None, None)
        self.assertTrue(s.in_scope_host('www.example.com'))
        s = Scope([], [], [])
        self.assertFalse(s.in_scope_host('www.example.com'))


if __name__ == '__main__':
    unittest.main()
