// Shared utilities and components for creator pages

const formatMoney = (value) => {
  const amount = Number(value || 0);
  return `Rs. ${amount.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`;
};

const getCampaignBudget = (campaign) => {
  if (!campaign) return 'Rs. 0';
  const min = campaign.budget_min ?? campaign.budget ?? campaign.myBid?.amount ?? 0;
  const max = campaign.budget_max ?? min;
  return min === max ? formatMoney(min) : `${formatMoney(min)} - ${formatMoney(max)}`;
};

const getInitial = (name) => (name || 'U').trim().charAt(0).toUpperCase();

function EmptyPanel({ text }) {
  return <div className="pcd-empty-panel">{text}</div>;
}

function CampaignGrid({ items, empty, renderActions }) {
  if (!items.length) return <EmptyPanel text={empty} />;

  return (
    <div className="pcd-campaign-grid">
      {items.map((campaign) => (
        <article key={campaign.id} className="pcd-campaign-card">
          <div>
            <h3>{campaign.title}</h3>
            <span className={`pcd-status ${campaign.status}`}>{(campaign.status || 'active').replace('_', ' ')}</span>
          </div>
          <p>{campaign.brief_text ? `${campaign.brief_text.substring(0, 150)}${campaign.brief_text.length > 150 ? '...' : ''}` : 'Creator campaign brief'}</p>
          <dl>
            <div><dt>Budget</dt><dd>{getCampaignBudget(campaign)}</dd></div>
            <div><dt>Brand</dt><dd>{campaign.business_nickname || campaign.brand_handle || 'Brand'}</dd></div>
            <div><dt>Objectives</dt><dd>{campaign.objectives?.length || 0}</dd></div>
          </dl>
          <div className="pcd-card-actions">{renderActions(campaign)}</div>
        </article>
      ))}
    </div>
  );
}

export { formatMoney, getCampaignBudget, getInitial, EmptyPanel, CampaignGrid };
