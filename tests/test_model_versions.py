"""GPT Image versions are parsed, so a new release gets the right settings unaided."""


def test_new_gpt_image_versions_get_the_newest_settings_and_moderation_default():
    from providers.gpt_image_moderation import apply_gpt_image_moderation_default, is_gpt_image_model
    from providers.model_versions import gpt_image_version
    from services.media_catalog import GPT_IMAGE_2, GPT_IMAGE_25, image_profile, prepare_image_payload

    assert gpt_image_version("gguu:gpt-image-2.6") == (2, 6)
    assert gpt_image_version("gpt-image-2-free") == (2, 0)
    for model in ("gpt-image-2.6", "gpt-image-2.6-sunburst", "gpt-image-2.6-flare", "gpt-image-3"):
        assert image_profile("gguu", model) == GPT_IMAGE_25, model
    assert image_profile("gguu", "gpt-image-2") == GPT_IMAGE_2
    assert image_profile("cloudflare", "openai/gpt-image-2.6-sunburst").max_edge == 0
    prepared = prepare_image_payload("gguu", "gpt-image-2.6", {"model": "gguu:gpt-image-2.6", "prompt": "x",
                                                                "quality": "max", "size": "3840x2160"})
    assert (prepared["quality"], prepared["size"]) == ("max", "3840x2160")
    for model in ("gpt-image-2.6", "gguu:gpt-image-2.6-sunburst", "openai/gpt-image-3"):
        assert apply_gpt_image_moderation_default({"model": model, "prompt": "x"})[0]["moderation"] == "low", model
    for model in ("gpt-image-25", "gguu:gpt-image@latest", "chatgpt-image-latest", "gemini-3-pro-image"):
        assert not is_gpt_image_model(model), model
