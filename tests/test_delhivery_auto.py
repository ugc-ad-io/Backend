import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock


class CourierError(Exception):
    def __init__(self, status_code, detail):
        self.detail = detail


def namespace(shipment):
    tree = ast.parse((Path(__file__).parents[1] / 'server.py').read_text(encoding='utf-8'))
    names = {'generate_saved_shipping_label', 'auto_generate_shipping_label'}
    nodes = [n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name in names]
    ns = dict(HTTPException=CourierError, find_shipment=AsyncMock(return_value=shipment),
              delhivery_token=lambda: 'configured', ShipLabelRequest=lambda **kw: kw,
              person_deal_id=lambda c, uid: c['id'] + '~' + uid,
              create_shipping_label=AsyncMock(return_value={'tracking_number': 'AWB123'}),
              shipment_match_filter=AsyncMock(return_value={'creator_id': 'creator-b'}),
              now_iso=lambda: 'now',
              db=SimpleNamespace(users=SimpleNamespace(find_one=AsyncMock(return_value={'id': 'brand'})),
                                 shipments=SimpleNamespace(update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1)))))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'shipping', 'exec'), ns)
    return ns


CAMPAIGN = {'id': 'campaign', 'business_id': 'brand'}
READY = {'pickup_address': {'line1': 'Brand warehouse'},
         'delivery_address': {'line1': 'Confirmed address'},
         'product': {'description': 'Sample', 'weight': 0.5, 'dimensions': {}}}


def test_saved_details_target_correct_creator():
    ns = namespace(READY)
    assert asyncio.run(ns['auto_generate_shipping_label'](CAMPAIGN, 'creator-b'))['tracking_number'] == 'AWB123'
    deal, payload, brand = ns['create_shipping_label'].call_args.args
    assert deal == 'campaign~creator-b'
    assert payload['pickup_address'] == READY['pickup_address']
    assert payload['weight'] == 0.5


def test_missing_confirmation_waits():
    ns = namespace({**READY, 'delivery_address': None})
    assert asyncio.run(ns['auto_generate_shipping_label'](CAMPAIGN, 'creator-b')) is None
    ns['create_shipping_label'].assert_not_called()


def test_existing_awb_reused():
    ns = namespace({**READY, 'tracking_number': 'EXISTING'})
    assert asyncio.run(ns['generate_saved_shipping_label'](CAMPAIGN, 'creator-b'))['tracking_number'] == 'EXISTING'
    ns['create_shipping_label'].assert_not_called()


def test_rejection_preserves_details_for_retry():
    ns = namespace(READY)
    ns['create_shipping_label'].side_effect = CourierError(502, 'Courier rejected pickup')
    assert asyncio.run(ns['auto_generate_shipping_label'](CAMPAIGN, 'creator-b')) == {'label_error': 'Courier rejected pickup'}
    update = ns['db'].shipments.update_one.call_args.args[1]['$set']
    assert update['label_error'] == 'Courier rejected pickup'
    assert 'pickup_address' not in update
