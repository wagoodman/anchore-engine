import json
import os

import pytest

from tests.functional.services.api.images import (
    get_image_digest,
    get_image_id,
    wait_for_image_to_analyze,
)
from tests.functional.services.utils.http_utils import (
    APIResponse,
    get_api_conf,
    http_get,
)

test_images = [
    "docker.io/anchore/test_images:vulnerabilities-alpine",
    "docker.io/anchore/test_images:vulnerabilities-centos",
]


def sort_content(body):
    body["content"].sort(key=lambda result: result["package"])
    for result in body["content"]:
        result["cpes"].sort()
        if "licenses" in result:
            result["licenses"].sort()


@pytest.mark.parametrize("test_tag", test_images, scope="class")
class TestImageContent:
    @pytest.fixture(scope="class")
    def add_and_wait_for_image(self, test_tag, add_image_with_teardown):
        add_response = add_image_with_teardown(test_tag)
        image_id = get_image_id(add_response)
        wait_for_image_to_analyze(image_id, api_conf=get_api_conf)
        return add_response

    @pytest.fixture
    def read_expected_content(self):
        def _read_expected_content(type, filename):
            expected_content_path = os.path.join(
                os.path.dirname(__file__), "expected_content", type, filename
            )
            return json.load(open(expected_content_path))

        return _read_expected_content

    def test_image_os_content(self, add_and_wait_for_image, read_expected_content):
        image_digest = get_image_digest(add_and_wait_for_image)

        resp = http_get(["images", image_digest, "content", "os"], config=get_api_conf)
        assert resp == APIResponse(200)

        expected_content = read_expected_content("os", f"{image_digest}.json")

        sort_content(resp.body)
        sort_content(expected_content)

        assert expected_content == resp.body
        for result in resp.body["content"]:
            assert result["sourcepkg"] not in ["", None]

    def test_image_java_content(self, add_and_wait_for_image, read_expected_content):
        image_digest = get_image_digest(add_and_wait_for_image)

        resp = http_get(
            ["images", image_digest, "content", "java"], config=get_api_conf
        )
        assert resp == APIResponse(200)

        expected_content = read_expected_content("java", f"{image_digest}.json")

        sort_content(resp.body)
        sort_content(expected_content)

        assert expected_content == resp.body
        for result in resp.body["content"]:
            assert result["version"] not in ["", None]
