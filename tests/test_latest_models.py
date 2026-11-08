"""Route placeholders that follow a provider's newest release (services.latest_models)."""

from unittest.mock import patch

# Load the route and catalog modules in the order the app does; importing
# provider_catalog_service first hits an import cycle through model_registry.
import services.auto_route_service  # noqa: F401
from services import latest_models
from services.latest_models import order_releases

# GGUU's gpt-image group key listed these on 2026-11-08, after GPT Image 2.6 shipped.
GGUU_NOV_2026 = ("gpt-image-2", "gpt-image-2.5-flare", "gpt-image-2.5-sunburst", "gpt-image-2.6")


def test_latest_puts_the_newest_version_first_and_sunburst_before_flare():
    assert order_releases("gpt-image", "latest", GGUU_NOV_2026) == (
        "gpt-image-2.6", "gpt-image-2.5-sunburst", "gpt-image-2.5-flare", "gpt-image-2")


def test_a_release_with_variants_takes_the_lead_and_the_list_stays_capped():
    listed = GGUU_NOV_2026 + ("gpt-image-2.6-flare", "gpt-image-2.6-sunburst")
    assert order_releases("gpt-image", "latest", listed) == (
        "gpt-image-2.6-sunburst", "gpt-image-2.6", "gpt-image-2.6-flare", "gpt-image-2.5-sunburst")


def test_latest_fast_tries_speed_variants_first_and_leaves_out_sunburst():
    assert order_releases("gpt-image", "latest-fast", GGUU_NOV_2026) == (
        "gpt-image-2.5-flare", "gpt-image-2.6", "gpt-image-2")
    assert order_releases("gpt-image", "latest-fast", GGUU_NOV_2026 + ("gpt-image-2.6-flare",))[:2] == (
        "gpt-image-2.6-flare", "gpt-image-2.5-flare")


def test_other_families_dated_snapshots_and_unversioned_names_are_left_out():
    listed = ("gpt-image-2-2026-04-21", "gpt-image-2.5-sunburst-2026-09-08", "chatgpt-image-latest",
              "gpt-image-2", "openai/gpt-image-2.6", "grok-imagine-image", "grok-imagine-image-lite",
              "grok-imagine-image-2.0")
    assert order_releases("gpt-image", "latest", listed) == ("gpt-image-2",)
    assert order_releases("openai/gpt-image", "latest", listed) == ("openai/gpt-image-2.6",)
    assert order_releases("grok-imagine-image", "latest", listed) == ("grok-imagine-image-2.0",)


def test_versions_compare_as_numbers():
    assert order_releases("gpt-image", "latest", ("gpt-image-2.9", "gpt-image-2.10"))[0] == "gpt-image-2.10"


def test_placeholder_syntax():
    assert latest_models.parse_placeholder("gpt-image@latest") == ("gpt-image", "latest")
    assert latest_models.parse_placeholder("gpt-image@latest-fast") == ("gpt-image", "latest-fast")
    for model in ("gpt-image-2.6", "claude-3-5-sonnet@20240620", "GPT-Image@latest", "gpt-image@latest-slow", "@latest"):
        assert latest_models.parse_placeholder(model) is None, model
    assert latest_models.is_placeholder("gguu:gpt-image@latest")
    assert not latest_models.is_placeholder("gpt-image@latest")
    assert not latest_models.is_placeholder("cloudflare:@cf/leonardo/lucid-origin")


def test_resolve_reads_the_live_catalog_and_falls_back_to_the_built_in_list():
    from services.provider_catalog_service import ProviderCatalogModel, ProviderCatalogService

    live = [ProviderCatalogModel("gguu", model, "t") for model in GGUU_NOV_2026]
    live.append(ProviderCatalogModel("ce-image", "gpt-image-9", "t"))
    with patch.object(ProviderCatalogService, "list_models", return_value=live):
        assert latest_models.resolve("gguu:gpt-image@latest") == (
            "gguu:gpt-image-2.6", "gguu:gpt-image-2.5-sunburst", "gguu:gpt-image-2.5-flare", "gguu:gpt-image-2")
    built_in = ("gguu:gpt-image-2.5-sunburst", "gguu:gpt-image-2.5", "gguu:gpt-image-2.5-flare", "gguu:gpt-image-2")
    with patch.object(ProviderCatalogService, "list_models", return_value=[]):
        assert latest_models.resolve("gguu:gpt-image@latest") == built_in
        # A provider with no listed model of the family adds nothing.
        assert latest_models.resolve("openai:gpt-image@latest") == ()
    # A catalog outage must not stop dispatch.
    with patch.object(ProviderCatalogService, "list_models", side_effect=RuntimeError("D1 unavailable")):
        assert latest_models.resolve("gguu:gpt-image@latest") == built_in
    assert latest_models.resolve("gguu:gpt-image-2") == ("gguu:gpt-image-2",)


def test_expanding_a_route_keeps_the_first_copy_and_the_route_limit():
    with patch.object(latest_models, "provider_model_ids", return_value=GGUU_NOV_2026):
        assert latest_models.expand_candidates(
            ("gguu:gpt-image-2", "gguu:gpt-image@latest", "latix:gpt-image-2"), 4) == (
            "gguu:gpt-image-2", "gguu:gpt-image-2.6", "gguu:gpt-image-2.5-sunburst", "gguu:gpt-image-2.5-flare")


def test_an_approved_canary_placeholder_approves_the_models_it_means_now():
    from services.canary_traffic import CanaryConfig

    canary = CanaryConfig(True, "live", 50, 50, "1", ("gguu:gpt-image@latest",))
    with patch.object(latest_models, "provider_model_ids", return_value=GGUU_NOV_2026):
        expanded = latest_models.expand_canary(canary, ("gguu:gpt-image-2.6", "gguu:gpt-image-2.5-sunburst", "latix:x"))
    assert expanded.approved_candidates == ("gguu:gpt-image-2.6", "gguu:gpt-image-2.5-sunburst")
    plain = CanaryConfig(True, "live", 50, 50, "1", ("latix:x",))
    assert latest_models.expand_canary(plain, ("latix:x",)) is plain
