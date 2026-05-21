import { createBrowserRouter } from "react-router";
import { RootLayout }          from "./components/RootLayout";
import { BrandLayout }         from "./components/BrandLayout";
import { Dashboard }           from "./components/Dashboard";
import { BrowseBriefs }        from "./components/BrowseBriefs";
import { MyDeals }             from "./components/MyDeals";
import { Payouts }             from "./components/Payouts";
import { Messages }            from "./components/Messages";
import { Profile }             from "./components/Profile";
import { Settings }            from "./components/Settings";
import { NotFound }            from "./components/NotFound";
import { BrandDashboard }      from "./components/BrandDashboard";
import { BrandPlaceholder }    from "./components/BrandPlaceholder";
import { PostBrief }           from "./components/PostBrief";
import { BrandDealRoom }       from "./components/BrandDealRoom";
import { BrandBrowseCreators } from "./components/BrandBrowseCreators";
import { BrowseCreatorsPage }  from "./components/BrowseCreatorsPage";
import { BrandWallet }         from "./components/BrandWallet";
import { BrandSettings }       from "./components/BrandSettings";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: RootLayout,
    children: [
      { index: true,      Component: Dashboard    },
      { path: "briefs",   Component: BrowseBriefs },
      { path: "deals",    Component: MyDeals      },
      { path: "payouts",  Component: Payouts      },
      { path: "messages", Component: Messages     },
      { path: "profile",  Component: Profile      },
      { path: "settings", Component: Settings     },
      { path: "*",        Component: NotFound     },
    ],
  },
  // Standalone full-page — own sidebar + topbar (no BrandLayout wrapper)
  {
    path: "/brand/applications",
    Component: BrowseCreatorsPage,
  },
  {
    path: "/brand",
    Component: BrandLayout,
    children: [
      { index: true,          Component: BrandDashboard   },
      { path: "post-brief",   Component: PostBrief        },
      { path: "deals",        Component: BrandDealRoom    },
      { path: "messages",     Component: Messages         },
      { path: "wallet",       Component: BrandWallet      },
      { path: "profile",      Component: BrandPlaceholder },
      { path: "settings",     Component: BrandSettings    },
      { path: "*",            Component: NotFound         },
    ],
  },
]);