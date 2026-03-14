"""NAICS keyword-to-code mapping for ThreatConnect NAICS Tags.

See: https://knowledge.threatconnect.com/docs/naics-ai-industry-classification#naics-codes
Tags are formatted as: NAICS: <code> - <sector or subsector name>
"""

from typing import List

# Sector and subsector (code, name) pairs from ThreatConnect NAICS AI Industry Classification.
NAICS_ENTRIES: List[tuple] = [
    # 11 - Agriculture, Forestry, Fishing and Hunting
    ("11", "Agriculture, Forestry, Fishing and Hunting"),
    ("111", "Crop Production"),
    ("112", "Animal Production and Aquaculture"),
    ("113", "Forestry and Logging"),
    ("114", "Fishing, Hunting and Trapping"),
    ("115", "Support Activities for Agriculture and Forestry"),
    # 21 - Mining, Quarrying, Oil and Gas Extraction
    ("21", "Mining, Quarrying, Oil and Gas Extraction"),
    ("211", "Oil and Gas Extraction"),
    ("212", "Mining (except Oil and Gas)"),
    ("213", "Support Activities for Mining"),
    # 22 - Utilities
    ("22", "Utilities"),
    ("221", "Utilities"),
    # 23 - Construction
    ("23", "Construction"),
    ("236", "Construction of Buildings"),
    ("237", "Heavy and Civil Engineering Construction"),
    ("238", "Specialty Trade Contractors"),
    # 31 - Manufacturing - Food and Textile
    ("31", "Manufacturing - Food and Textile"),
    ("311", "Food Manufacturing"),
    ("312", "Beverage and Tobacco Product Manufacturing"),
    ("313", "Textile Mills"),
    ("314", "Textile Product Mills"),
    ("315", "Apparel Manufacturing"),
    ("316", "Leather and Allied Product Manufacturing"),
    # 32 - Manufacturing - Wood and Plastics
    ("32", "Manufacturing - Wood and Plastics"),
    ("321", "Wood Product Manufacturing"),
    ("322", "Paper Manufacturing"),
    ("323", "Printing and Related Support Activities"),
    ("324", "Petroleum and Coal Products Manufacturing"),
    ("325", "Chemical Manufacturing"),
    ("326", "Plastics and Rubber Products Manufacturing"),
    ("327", "Nonmetallic Mineral Product Manufacturing"),
    # 33 - Manufacturing - Metal, Electronics and Other
    ("33", "Manufacturing - Metal, Electronics and Other"),
    ("331", "Primary Metal Manufacturing"),
    ("332", "Fabricated Metal Product Manufacturing"),
    ("333", "Machinery Manufacturing"),
    ("334", "Computer and Electronic Product Manufacturing"),
    ("335", "Electrical Equipment, Appliance, Component Manufacturing"),
    ("336", "Transportation Equipment Manufacturing"),
    ("337", "Furniture and Related Product Manufacturing"),
    ("339", "Miscellaneous Manufacturing"),
    # 42 - Wholesale Trade
    ("42", "Wholesale Trade"),
    ("423", "Merchant Wholesalers, Durable Goods"),
    ("424", "Merchant Wholesalers, Nondurable Goods"),
    ("425", "Wholesale Trade Agents and Brokers"),
    # 44 - Retail Trade - Auto, Food, Home
    ("44", "Retail Trade - Auto, Food, Home"),
    ("441", "Motor Vehicle and Parts Dealers"),
    ("444", "Building Material and Garden Equipment and Supplies Dealers"),
    ("445", "Food and Beverage Retailers"),
    ("449", "Furniture, Home Furnishings, Electronics, Appliance Retailers"),
    # 45 - Retail Trade - Fuel, Other
    ("45", "Retail Trade - Fuel, Other"),
    ("455", "General Merchandise Retailers"),
    ("456", "Health and Personal Care Retailers"),
    ("457", "Gasoline Stations and Fuel Dealers"),
    ("458", "Clothing, Clothing Accessories, Shoe, Jewelry Retailers"),
    ("459", "Sporting Goods, Hobby, Musical Instrument, Book, Miscellaneous Retailers"),
    # 48 - Transportation
    ("48", "Transportation"),
    ("481", "Air Transportation"),
    ("482", "Rail Transportation"),
    ("483", "Water Transportation"),
    ("484", "Truck Transportation"),
    ("485", "Transit and Ground Passenger Transportation"),
    ("486", "Pipeline Transportation"),
    ("487", "Scenic and Sightseeing Transportation"),
    ("488", "Support Activities for Transportation"),
    # 49 - Couriers and Warehousing
    ("49", "Couriers and Warehousing"),
    ("491", "Postal Service"),
    ("492", "Couriers and Messengers"),
    ("493", "Warehousing and Storage"),
    # 51 - Information
    ("51", "Information"),
    ("512", "Motion Picture and Sound Recording Industries"),
    ("513", "Publishing Industries"),
    ("516", "Broadcasting and Content Providers"),
    ("517", "Telecommunications"),
    ("518", "Computing Infrastructure Providers, Data Processing, Web Hosting, Related Services"),
    ("519", "Web Search Portals, Libraries, Archives, Other Information Services"),
    # 52 - Finance and Insurance
    ("52", "Finance and Insurance"),
    ("521", "Monetary Authorities-Central Bank"),
    ("522", "Credit Intermediation and Related Activities"),
    ("523", "Securities, Commodity Contracts, Other Financial Investments and Related Activities"),
    ("524", "Insurance Carriers and Related Activities"),
    ("525", "Funds, Trusts, Other Financial Vehicles"),
    # 53 - Real Estate and Rental and Leasing
    ("53", "Real Estate and Rental and Leasing"),
    ("531", "Real Estate"),
    ("532", "Rental and Leasing Services"),
    ("533", "Lessors of Nonfinancial Intangible Assets (except Copyrighted Works)"),
    # 54 - Professional, Scientific, Technical Services
    ("54", "Professional, Scientific, Technical Services"),
    ("541", "Professional, Scientific, Technical Services"),
    # 55 - Management of Companies and Enterprises
    ("55", "Management of Companies and Enterprises"),
    ("551", "Management of Companies and Enterprises"),
    # 56 - Administrative and Support and Waste Management and Remediation Services
    ("56", "Administrative and Support and Waste Management and Remediation Services"),
    ("561", "Administrative and Support Services"),
    ("562", "Waste Management and Remediation Services"),
    # 61 - Educational Services
    ("61", "Educational Services"),
    ("611", "Educational Services"),
    # 62 - Health Care and Social Assistance
    ("62", "Health Care and Social Assistance"),
    ("621", "Ambulatory Health Care Services"),
    ("622", "Hospitals"),
    ("623", "Nursing and Residential Care Facilities"),
    ("624", "Social Assistance"),
    # 71 - Arts, Entertainment, Recreation
    ("71", "Arts, Entertainment, Recreation"),
    ("711", "Performing Arts, Spectator Sports, Related Industries"),
    ("712", "Museums, Historical Sites, Similar Institutions"),
    ("713", "Amusement, Gambling, Recreation Industries"),
    # 72 - Accommodation and Food Services
    ("72", "Accommodation and Food Services"),
    ("721", "Accommodation"),
    ("722", "Food Services and Drinking Places"),
    # 81 - Other Services (except Public Administration)
    ("81", "Other Services (except Public Administration)"),
    ("811", "Repair and Maintenance"),
    ("812", "Personal and Laundry Services"),
    ("813", "Religious, Grantmaking, Civic, Professional, Similar Organizations"),
    ("814", "Private Households"),
    # 92 - Public Administration
    ("92", "Public Administration"),
    ("921", "Executive, Legislative, Other General Government Support"),
    ("922", "Justice, Public Order, Safety Activities"),
    ("923", "Administration of Human Resource Programs"),
    ("924", "Administration of Environmental Quality Programs"),
    ("925", "Administration of Housing Programs, Urban Planning, Community Development"),
    ("926", "Administration of Economic Programs"),
    ("927", "Space Research and Technology"),
    ("928", "National Security and International Affairs"),
]


def naics_tags_for_keyword(tags: List[str]) -> List[str]:
    """Return ThreatConnect-format NAICS tags whose sector/subsector name contains the given text.

    Matching is case-insensitive substring. Empty input returns no tags.
    Example: "finance" -> ["NAICS: 52 - Finance and Insurance", ...]
    """
    result: List[str] = []
    for tag in tags:
        normalized = (tag or "").strip().lower()
        for code, name in NAICS_ENTRIES:
            if normalized in name.lower():
                result.append(f"NAICS: {code} - {name}")
                break
    return result
