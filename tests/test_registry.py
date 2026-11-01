"""Registry invariants: unique ids, valid categories and complete field specs."""

from __future__ import annotations

import unittest

from nulltrace.modules import CATEGORY_ORDER, all_modules, find, grouped


class RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.modules = all_modules()

    def test_has_modules(self) -> None:
        self.assertGreaterEqual(len(self.modules), 31)

    def test_ids_unique(self) -> None:
        ids = [module.id for module in self.modules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_are_identifiers(self) -> None:
        for module in self.modules:
            self.assertRegex(module.id, r"^[a-z][a-z0-9_]*$")

    def test_categories_known(self) -> None:
        for module in self.modules:
            self.assertIn(module.category, CATEGORY_ORDER)

    def test_titles_and_summaries_present(self) -> None:
        for module in self.modules:
            self.assertTrue(module.title.strip(), module.id)
            self.assertTrue(module.summary.strip(), module.id)
            self.assertTrue(callable(module.run), module.id)

    def test_field_names_unique_per_module(self) -> None:
        for module in self.modules:
            names = [field.name for field in module.fields]
            self.assertEqual(len(names), len(set(names)), module.id)

    def test_choice_fields_have_valid_defaults(self) -> None:
        for module in self.modules:
            for field in module.fields:
                self.assertIn(field.kind, ("text", "multiline", "choice", "checkbox", "file"))
                if field.kind == "choice":
                    self.assertTrue(field.choices, f"{module.id}.{field.name}")
                    if field.default:
                        self.assertIn(field.default, field.choices,
                                      f"{module.id}.{field.name}")

    def test_grouped_covers_all(self) -> None:
        groups = grouped()
        self.assertEqual(sum(len(items) for items in groups.values()), len(self.modules))
        self.assertEqual(list(groups), [c for c in CATEGORY_ORDER if c in groups])

    def test_find(self) -> None:
        first = self.modules[0]
        self.assertIs(find(first.id), first)
        self.assertIsNone(find("nope"))


if __name__ == "__main__":
    unittest.main()
