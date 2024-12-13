import networkx as nx
import matplotlib.pyplot as plt
import graphviz
from AttackTree.attack_node import AttackNode
from AttackTree.CVSS import Metric
from graphviz import Digraph
import xml.etree.ElementTree as ET
import numpy as np
from scipy.optimize import curve_fit
import numpy as np
import matplotlib.pyplot as plt
import requests
import json
from nvd_api import NvdApiClient
import re
import datetime

CVSS_V31_STR = "cvssMetricV31"
CVSS_V30_STR = "cvssMetricV30"
CVSS_V20_STR = "cvssMetricV2"

nvd_api_key = "3ce37055-92b4-455b-94f5-a52df634f439"
client = NvdApiClient()
client = NvdApiClient(wait_time=1 * 1000, api_key=nvd_api_key)
id_to_cves_map_unicar_agil = {
    "0" :["CVE-2023-36321", "CVE-2023-26257", "CVE-2022-39837", "CVE-2022-39836", "CVE-2022-21624", "CVE-2020-10282", "CVE-2015-5611"],
    "1" :["CVE-2023-36321", "CVE-2023-26257", "CVE-2022-39837", "CVE-2022-39836", "CVE-2022-21624","CVE-2022-0878", "CVE-2020-10282", "CVE-2015-5611"],
    "1.1" :["CVE-2024-9981", "CVE-2024-9634", "CVE-2022-20753", "CVE-2022-20688", "CVE-2021-46609", "CVE-2021-46601", "CVE-2012-0443"],
    "1.1.1" :[ "CVE-2024-51500", "CVE-2023-41896", "CVE-2023-32156", "CVE-2022-24750", "CVE-2020-10922", "CVE-2019-10938", "CVE-2018-11452", "CVE-2016-4028"],
    "1.1.2" :["CVE-2022-45179", "CVE-2022-26950", "CVE-2021-30650", "CVE-2020-6365", "CVE-2020-29537", "CVE-2020-14225", "CVE-2013-6308", "CVE-2013-4200"],
    "1.1.3" :["CVE-2022-48761", "CVE-2022-20933", "CVE-2022-20817", "CVE-2021-29490", "CVE-2019-1983", "CVE-2018-21062"],
    "1.2" :[ "CVE-2023-47705", "CVE-2023-42503", "CVE-2023-37069", "CVE-2021-44538", "CVE-2021-21343", "CVE-2019-8157", "CVE-2016-9093"],
    "1.2.1" :[ "CVE-2014-2359", "CVE-2013-4062"],
    "1.2.2" :["CVE-2024-20275", "CVE-2022-29878", "CVE-2021-46390", "CVE-2021-41025", "CVE-2020-26282", "CVE-2019-10964", "CVE-2018-2402", "CVE-2006-6476"],
    "1.2.3" :["CVE-2018-11401", "CVE-2017-9658"],
    "1.3" :["CVE-2024-45117", "CVE-2024-41808", "CVE-2022-31705", "CVE-2021-38096", "CVE-2020-3967", "CVE-2020-3958", "CVE-2018-9530", "CVE-2017-3011"],
    "1.3.1" :["CVE-2024-5711", "CVE-2024-3841", "CVE-2024-34061", "CVE-2023-35947", "CVE-2022-1521", "CVE-2021-24884", "CVE-2020-7697", "CVE-2020-4811", "CVE-2016-10043"],
    "1.3.2" :["CVE-2024-4498", "CVE-2022-45910", "CVE-2021-32651", "CVE-2019-14654", "CVE-2015-6237", "CVE-2004-0411"],
    "1.3.3" :["CVE-2022-39250",],
    "1.4" :["CVE-2024-48442", "CVE-2024-4781", "CVE-2024-39886", "CVE-2024-39223", "CVE-2024-31469", "CVE-2024-28957", "CVE-2023-28971", "CVE-2022-32509"],
    "1.4.1" :["CVE-2022-32509", "CVE-2019-14261"],
    "1.4.2" :["CVE-2024-9314", "CVE-2024-8624", "CVE-2023-4449", "CVE-2023-43794", "CVE-2022-32224", "CVE-2021-41128", "CVE-2020-4035", "CVE-2019-4391"],
    "1.4.3" :["CVE-2024-44097", "CVE-2023-51741", "CVE-2023-51740", "CVE-2023-39245", "CVE-2023-33982", "CVE-2019-10926", "CVE-2013-0570"],
    "2" :["CVE-2024-47616", "CVE-2024-36933", "CVE-2023-45868", "CVE-2023-28985", "CVE-2022-3029", "CVE-2021-23843", "CVE-2020-27146", "CVE-2020-2711"],
    "2.1" :["CVE-2024-8460", "CVE-2024-44113", "CVE-2024-39562", "CVE-2023-33985", "CVE-2022-26866", "CVE-2021-0214", "CVE-2020-0293", "CVE-2019-18314"],
    "2.1.1" :["CVE-2024-45042", "CVE-2024-1183", "CVE-2023-35163", "CVE-2023-28985", "CVE-2021-41590", "CVE-2020-24142", "CVE-2019-7579", "CVE-2012-3724"],
    "2.1.2" :["CVE-2024-47174", "CVE-2023-33983", "CVE-2021-3418", "CVE-2020-15134", "CVE-2020-15133", "CVE-2018-8039", "CVE-2015-5505", "CVE-2014-4825"],
    "2.1.3" :["CVE-2024-5526", "CVE-2024-36105", "CVE-2023-44183", "CVE-2023-36841", "CVE-2023-22480", "CVE-2022-23813", "CVE-2022-23037", "CVE-2021-3060", "CVE-2020-6970"],
    "2.2" :["CVE-2024-3435", "CVE-2024-1488", "CVE-2023-37325", "CVE-2022-33683", "CVE-2022-31481", "CVE-2021-1619", "CVE-2020-29492", "CVE-2019-12418", "CVE-2018-4841"],
    "2.2.1" :["CVE-2024-9050", "CVE-2024-45005", "CVE-2023-5358", "CVE-2023-45228", "CVE-2021-21353", "CVE-2020-3492", "CVE-2019-15661", "CVE-2018-14867", "CVE-2017-8333"],
    "2.2.2" :["CVE-2023-37581", "CVE-2022-42488", "CVE-2022-30313", "CVE-2021-47027", "CVE-2020-7251", "CVE-2019-15685"],
    "2.2.3" :["CVE-2024-51500", "CVE-2024-42368", "CVE-2024-37166", "CVE-2023-6116", "CVE-2023-4667", "CVE-2023-33238", "CVE-2022-25293", "CVE-2020-8976"],
    "2.3" :["CVE-2024-8862", "CVE-2024-26685", "CVE-2023-6578", "CVE-2023-4558", "CVE-2023-41918", "CVE-2023-37068", "CVE-2022-30772", "CVE-2021-42698", "CVE-2020-11150", "CVE-2017-20180"],
    "2.3.1" :["CVE-2024-9314", "CVE-2024-8030", "CVE-2023-4449", "CVE-2023-25196", "CVE-2022-36799", "CVE-2021-43944", "CVE-2020-7577", "CVE-2019-18618"],
    "2.3.2" :["CVE-2024-8583", "CVE-2024-32888", "CVE-2023-46737", "CVE-2023-41877", "CVE-2022-39273", "CVE-2022-34661", "CVE-2021-47094", "CVE-2021-36747", "CVE-2021-29974"],
    "2.3.3" :["CVE-2024-39420", "CVE-2024-29039", "CVE-2024-0832", "CVE-2023-46132", "CVE-2022-30313", "CVE-2022-25218", "CVE-2022-20547", "CVE-2021-44538", "CVE-2017-18312"],
    "2.4" :["CVE-2024-9953", "CVE-2024-8405", "CVE-2024-43759", "CVE-2023-2778", "CVE-2023-26104", "CVE-2022-43392", "CVE-2022-42319"],
    "2.4.1" :["CVE-2022-23989", "CVE-2022-22191", "CVE-2022-22188", "CVE-2021-31368", "CVE-2021-1268", "CVE-2018-1000115", "CVE-2013-6701"],
    "2.4.2" :["CVE-2024-8890", "CVE-2024-42483", "CVE-2022-40675", "CVE-2022-30276", "CVE-2021-27876", "CVE-2021-20992", "CVE-2020-3162", "CVE-2020-12835"],
    "2.4.3" :["CVE-2024-32473", "CVE-2022-27584", "CVE-2022-27582", "CVE-2009-2208"],
    "3" :["CVE-2021-1071", "CVE-2021-1070"],
    "3.1" :["CVE-2024-9953", "CVE-2024-9471", "CVE-2024-8531", "CVE-2024-8254", "CVE-2020-26683", "CVE-2020-1800", "CVE-2019-5300", "CVE-2019-1737"],
    "3.1.1" :["CVE-2024-45813", "CVE-2023-37479", "CVE-2023-37903", "CVE-2022-29235", "CVE-2019-16943", "CVE-2019-16942", "CVE-2017-6784", "CVE-2017-3765"],
    "3.1.2" :["CVE-2024-5463", "CVE-2024-34198", "CVE-2024-25724", "CVE-2021-41499", "CVE-2021-25216", "CVE-2020-24133", "CVE-2020-13389", "CVE-2014-9629"],
    "3.1.3" :["CVE-2024-8770", "CVE-2023-23618", "CVE-2022-30280", "CVE-2022-24441", "CVE-2022-24349", "CVE-2021-41157", "CVE-2021-41139", "CVE-2019-12773", "CVE-2017-6955"],
    "3.2" :["CVE-2024-9143", "CVE-2024-5982", "CVE-2024-47765", "CVE-2023-6374", "CVE-2022-48461", "CVE-2022-41899", "CVE-2022-4134", "CVE-2022-39121"],
    "3.2.1" :["CVE-2024-41262", "CVE-2024-20385", "CVE-2023-29681", "CVE-2022-48308", "CVE-2022-48306", "CVE-2022-3913", "CVE-2019-1659", "CVE-2016-9928", "CVE-2007-5361"],
    "3.2.2" :["CVE-2024-47494", "CVE-2023-34597", "CVE-2022-39122", "CVE-2022-30339", "CVE-2019-1675", "CVE-2019-11561", "CVE-2013-1219", "CVE-2011-4022"],
    "3.3" :["CVE-2024-6403", "CVE-2024-4511", "CVE-2023-5035", "CVE-2023-4466", "CVE-2023-4204", "CVE-2022-42784", "CVE-2022-3007"],
    "4" :["CVE-2024-43460", "CVE-2024-39530", "CVE-2024-38182", "CVE-2021-40422", "CVE-2020-9049", "CVE-2020-10291", "CVE-2018-5401", "CVE-2014-2379"],
    "4.1" :["CVE-2024-45806", "CVE-2024-4151", "CVE-2024-35875", "CVE-2023-41047", "CVE-2022-33682", "CVE-2022-32224"],
    "4.1.1" :["CVE-2024-9314", "CVE-2024-8523", "CVE-2024-8309", "CVE-2024-7472", "CVE-2023-49096", "CVE-2023-46807", "CVE-2023-30557", "CVE-2022-3861"],
    "4.1.2" :["CVE-2024-9977", "CVE-2024-9325", "CVE-2023-5018", "CVE-2023-5012", "CVE-2022-3436", "CVE-2022-3414", "CVE-2019-1675", "CVE-2019-11741", "CVE-2015-10067"],
    "4.2" :["CVE-2023-4420", "CVE-2023-31410", "CVE-2022-24323", "CVE-2022-24322", "CVE-2019-5107", "CVE-2000-0809"],
    "4.2.1" :["CVE-2024-47174", "CVE-2023-33983", "CVE-2021-3418", "CVE-2020-15134", "CVE-2020-15133", "CVE-2018-8039", "CVE-2015-5505", "CVE-2014-4825"],
    "4.2.2" :["CVE-2024-47460", "CVE-2024-33518", "CVE-2023-47114", "CVE-2022-22204", "CVE-2022-22172", "CVE-2021-37182", "CVE-2020-7122"],
    "4.2.3" :["CVE-2024-30209", "CVE-2023-29529", "CVE-2023-22367", "CVE-2022-29482", "CVE-2021-3882", "CVE-2019-18201", "CVE-2019-9862"],
    "4.3" :["CVE-2024-26745", "CVE-2024-29184", "CVE-2023-4093", "CVE-2022-43684", "CVE-2021-0273", "CVE-2020-6828", "CVE-2019-5627", "CVE-2019-0058"],
    "4.3.1" :["CVE-2024-5535", "CVE-2024-1929", "CVE-2023-20256", "CVE-2022-42334", "CVE-2022-24740", "CVE-2022-24740", "CVE-2020-12826", "CVE-2018-15398"],
    "4.3.2" :["CVE-2024-23321", "CVE-2024-20315", "CVE-2022-32290", "CVE-2022-22249", "CVE-2021-37166", "CVE-2021-0289", "CVE-2020-25637", "CVE-2020-10271"],
    "5" :["CVE-2024-9986", "CVE-2024-9814", "CVE-2024-7668", "CVE-2023-6308", "CVE-2023-5829", "CVE-2023-3119", "CVE-2022-3583", "CVE-2022-3519"],
    "5.1" :["CVE-2024-29210", "CVE-2023-43848", "CVE-2021-20841", "CVE-2014-5431"],
    "5.1.1" :["CVE-2024-20034", "CVE-2023-49096", "CVE-2023-43794", "CVE-2023-0888", "CVE-2022-35942"],
    "5.1.2" :["CVE-2024-49955", "CVE-2024-20047", "CVE-2024-20046", "CVE-2023-32882", "CVE-2023-32662", "CVE-2023-0888", "CVE-2019-15069"],
    "5.2" :["CVE-2024-4498", "CVE-2024-2749", "CVE-2024-2505", "CVE-2022-45562", "CVE-2021-42833", "CVE-2019-8151", "CVE-2018-13109"],
    "5.2.1" :["CVE-2024-4498", "CVE-2024-2749", "CVE-2024-2505", "CVE-2022-45562", "CVE-2021-42833", "CVE-2019-8151", "CVE-2018-13109", "CVE-2020-10558"],
    "5.2.2" :["CVE-2024-8922", "CVE-2024-7573", "CVE-2024-7472", "CVE-2024-7388", "CVE-2023-37281", "CVE-2023-36922", "CVE-2021-4088", "CVE-2020-26295", "CVE-2019-1000007"],
    "5.3" :["CVE-2024-9953", "CVE-2024-8405", "CVE-2024-43759", "CVE-2023-2778", "CVE-2023-26104", "CVE-2022-43392", "CVE-2022-42319"],
    "5.3.1" :["CVE-2023-44188", "CVE-2017-1000411", "CVE-2022-23989", "CVE-2022-22191", "CVE-2022-22188", "CVE-2021-31368", "CVE-2021-1268", "CVE-2018-1000115", "CVE-2013-6701"],
    "5.3.2" :["CVE-2024-8890", "CVE-2024-22815", "CVE-2023-46892", "CVE-2023-33378", "CVE-2022-26034", "CVE-2021-33541"],
    "5.3.3" :["CVE-2024-32473", "CVE-2022-27584", "CVE-2022-27582", "CVE-2009-2208"],
    "6" :["CVE-2024-45806", "CVE-2023-46102", "CVE-2023-45321", "CVE-2022-45928", "CVE-2022-25219", "CVE-2021-37193", "CVE-2020-8479"],
    "6.1" :["CVE-2024-45806", "CVE-2023-46102", "CVE-2023-45321", "CVE-2022-45928", "CVE-2022-25219", "CVE-2021-37193", "CVE-2020-8479", "CVE-2020-2013"],
    "6.1.1" :["CVE-2024-32473", "CVE-2024-28812", "CVE-2023-38317", "CVE-2023-29092", "CVE-2023-27520", "CVE-2022-32290", "CVE-2021-3448"],
    "6.1.2" :["CVE-2024-36105", "CVE-2021-1561", "CVE-2018-0262", "CVE-2017-12249"],
    "6.1.3" :["CVE-2023-28630", "CVE-2023-23629", "CVE-2023-22488"],
    "6.2" :["CVE-2024-7727", "CVE-2023-48427", "CVE-2023-48256", "CVE-2022-39049", "CVE-2022-25218", "CVE-2021-46390", "CVE-2021-44486"],
    "6.2.1" :["CVE-2023-5973", "CVE-2021-42119", "CVE-2020-15212", "CVE-2019-10150"],
    "6.2.2" :["CVE-2024-8690", "CVE-2024-6654", "CVE-2024-46699", "CVE-2023-3280", "CVE-2023-27474", "CVE-2022-47529", "CVE-2022-23708"],
    "6.2.3" :["CVE-2024-38313", "CVE-2023-21016", "CVE-2023-20976", "CVE-2022-42544", "CVE-2020-5982", "CVE-2018-5741"]
}

id_to_cves_map_jeep = {
    "0": ["CVE-2015-5611", "CVE-2015-4630", "CVE-2014-4963", "CVE-2013-1418", "CVE-2013-6800", "CVE-2007-6496", "CVE-2006-6077", "CVE-2002-0393"],
    "1": ["CVE-2015-4961", "CVE-2015-2291", "CVE-2013-4737", "CVE-2006-3417", "CVE-2007-3464", "CVE-2005-3717", "CVE-2005-3715","CVE-2007-6041"],
    "1.1": ["CVE-2015-5611", "CVE-2012-3745", "CVE-2004-2626", "CVE-2004-0826", "CVE-2001-0044", "CVE-1999-0791"],
    "1.1.1": ["CVE-2015-5611", "CVE-2015-1538",  "CVE-2014-3386", "CVE-2013-2270", "CVE-2013-4874", "CVE-2010-0741", "CVE-2006-6336"],
    "1.1.2": ["CVE-2015-5611", "CVE-2015-1538",  "CVE-2014-3386", "CVE-2013-2270", "CVE-2013-4874", "CVE-2010-0741", "CVE-2006-6336"],
    "1.1.3": ["CVE-2014-6271", "CVE-2015-2746", "CVE-2015-2548", "CVE-2014-2935", "CVE-2012-5695", "CVE-2010-1132", "CVE-2008-7319"],
    "1.1.4": ["CVE-2014-9751", "CVE-2012-0465", "CVE-2010-3548", "CVE-2007-1561", "CVE-2002-1535", "CVE-2002-1484", "CVE-2002-0350", "CVE-1999-1289" ],
    "1.1.4.1": ["CVE-2010-3889", "CVE-2006-1242", "CVE-2005-2852", "CVE-2002-1484", "CVE-2002-0350","CVE-2000-0732", "CVE-1999-1373"],
    "1.1.4.2": ["CVE-2013-4877", "CVE-2013-3314", "CVE-2010-2860", "CVE-2008-3728", "CVE-2008-3068", "CVE-2006-1242", "CVE-2002-1484", "CVE-2002-0350",  "CVE-1999-1373"],
    "1.2": ["CVE-2015-3728", "CVE-2013-7136", "CVE-2012-2619", "CVE-2015-3912", "CVE-2008-5230", "CVE-2006-1176"],
    "1.2.1": ["CVE-2015-3728","CVE-2015-3912", "CVE-2015-0006", "CVE-2014-4364", "CVE-2011-5053", "CVE-2011-4507", "CVE-2009-4821"],
    "1.2.2": ["CVE-2015-3728","CVE-2015-3912", "CVE-2015-0006", "CVE-2014-4364", "CVE-2011-5053", "CVE-2011-4507", "CVE-2009-4821"],
    "1.2.2.1": ["CVE-2014-9687", "CVE-2014-2388", "CVE-2013-7043", "CVE-2011-5053", "CVE-2009-4821", "CVE-2009-4269", "CVE-2008-6549", "CVE-2007-5777", "CVE-2002-0395"],
    "1.2.2.2": ["CVE-2014-7243", "CVE-2015-0570", "CVE-2014-4162", "CVE-2014-1599", "CVE-2013-2310","CVE-2008-1269", "CVE-2007-5419"],
    "1.2.3": ["CVE-2014-7243", "CVE-2015-0570", "CVE-2014-4162", "CVE-2014-1599", "CVE-2013-2310","CVE-2008-1269", "CVE-2007-5419"],
    "1.2.4": ["CVE-2014-8244", "CVE-2014-4162", "CVE-2013-2599", "CVE-2013-2310", "CVE-2012-5968", "CVE-2005-0820"],
    "1.2.4.1": ["CVE-2010-3548", "CVE-2006-1242", "CVE-2002-1535", "CVE-1999-1373", "CVE-2002-1484", "CVE-2002-0350", "CVE-1999-1289"],
    "1.2.4.2": ["CVE-2014-8315","CVE-2013-0235", "CVE-2010-3982","CVE-2005-0315","CVE-2004-1759","CVE-2003-0472","CVE-2002-2052","CVE-2001-1030"],
    "1.2.4.3": ["CVE-2014-8315","CVE-2013-0235", "CVE-2010-3982","CVE-2005-0315","CVE-2004-1759","CVE-2003-0472","CVE-2002-2052","CVE-2001-1030","CVE-2002-0515"],
    "1.3": ["CVE-2014-0181", "CVE-2013-5166", "CVE-2009-2834", "CVE-2006-0671", "CVE-2002-0395", "CVE-2002-0394", "CVE-2002-0397"],
    "1.3.1": ["CVE-2014-8836", "CVE-2014-8671", "CVE-2014-4497", "CVE-2013-5717", "CVE-2012-3825", "CVE-2010-1084", "CVE-2006-6896" ],
    "1.3.2": ["CVE-2014-0181", "CVE-2014-4497", "CVE-2013-5166", "CVE-2009-2834", "CVE-2006-0671", "CVE-2002-0395", "CVE-2002-0394", "CVE-2002-0397"],
    "1.3.3": ["CVE-2014-0181", "CVE-2013-5717","CVE-2012-4687", "CVE-2012-3825", "CVE-2010-1084", "CVE-2009-2834", "CVE-2002-0394"],
    "1.3.4": ["CVE-2014-0181", "CVE-2013-5717", "CVE-2013-2599", "CVE-2005-0820", "CVE-2002-0395", "CVE-2002-0394", "CVE-2002-0397"],
    "1.3.4.1": ["CVE-2014-8315","CVE-2013-0235", "CVE-2010-3982","CVE-2006-1242", "CVE-2005-0315","CVE-2004-1759","CVE-2003-0472", "CVE-2002-0350", "CVE-2002-2052", "CVE-2002-1484","CVE-2001-1030", "CVE-1999-1373"],
    "1.3.4.2": ["CVE-2014-8315","CVE-2013-0235", "CVE-2010-3982","CVE-2005-0315","CVE-2004-1759","CVE-2003-0472","CVE-2002-2052","CVE-2001-1030","CVE-2002-0515"],
    "2": ["CVE-2015-5611","CVE-2012-6510","CVE-2009-2633","CVE-2008-4172","CVE-2007-6041","CVE-2006-1176"],
    "2.1": ["CVE-2014-3639", "CVE-2014-3635", "CVE-2013-1064", "CVE-2012-2737", "CVE-2011-1842", "CVE-2009-1189", "CVE-2006-6107"],
    "2.2": ["CVE-2015-5611", "CVE-2014-3639", "CVE-2014-3635", "CVE-2013-1064", "CVE-2012-2737", "CVE-2011-1842", "CVE-2009-1189", "CVE-2006-6107"],
    "3": ["CVE-2015-1312", "CVE-2014-6102", "CVE-2011-0834", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "3.1": ["CVE-2014-9781", "CVE-2014-9777", "CVE-2014-7252", "CVE-2013-7457", "CVE-2012-2619", "CVE-2004-1038"],
    "3.1.1": ["CVE-2013-4710", "CVE-2012-4221","CVE-2010-3548", "CVE-2006-6336", "CVE-2006-1242", "CVE-2005-4267"],
    "3.1.2": ["CVE-2015-2907", "CVE-2015-2906", "CVE-2014-4749", "CVE-2014-0974", "CVE-2008-1369", "CVE-2007-4323", "CVE-2007-4321"],
    "3.1.3": ["CVE-2015-0936", "CVE-2014-7169", "CVE-2014-3563", "CVE-2011-2916", "CVE-2005-2666", "CVE-2001-1585"],
    "3.1.4": ["CVE-2013-4852", "CVE-2013-4207", "CVE-2013-4206", "CVE-2012-3039", "CVE-2011-0437", "CVE-2008-0536"],
    "3.1.5": ["CVE-2015-5611", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "3.1.5.1": ["CVE-2015-5611", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "3.1.5.2": ["CVE-2015-5611", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "3.1.5.3": ["CVE-2015-5611", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "4": ["CVE-2015-5611", "CVE-2014-2073", "CVE-2011-0725", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "4.1": ["CVE-2015-2908", "CVE-2014-0683", "CVE-2013-4862", "CVE-2012-1805", "CVE-2010-2025", "CVE-2006-2560"],
    "4.1.1": ["CVE-2015-2908", "CVE-2014-0683", "CVE-2013-4862", "CVE-2012-1805", "CVE-2010-2025", "CVE-2006-2560"],
    "4.1.1.1": [ "CVE-2015-2908", "CVE-2014-0683", "CVE-2013-4862", "CVE-2012-1805", "CVE-2010-2025", "CVE-2006-2560"],
    "4.1.1.2": [ "CVE-2015-2908", "CVE-2014-0683", "CVE-2013-4862", "CVE-2012-1805", "CVE-2010-2025", "CVE-2006-2560"],
    "4.1.1.3": [ "CVE-2015-2908", "CVE-2014-0683", "CVE-2013-4862", "CVE-2012-1805", "CVE-2010-2025", "CVE-2006-2560"],
    "4.2": ["CVE-2015-2908", "CVE-2014-0683", "CVE-2013-4862", "CVE-2012-1805", "CVE-2010-2025", "CVE-2006-2560"],
    "4.2.1": ["CVE-2015-2875", "CVE-2014-9234", "CVE-2014-9510", "CVE-2012-2607", "CVE-2010-2656" ],
    "4.2.2": ["CVE-2014-3428", "CVE-2014-3052", "CVE-2013-6924", "CVE-2013-6920", "CVE-2010-2363", "CVE-2009-1561"],
    "4.2.2.1": [ "CVE-2014-9510", "CVE-2014-8886", "CVE-2014-4690", "CVE-2014-2718", "CVE-2012-2607", "CVE-2012-1328", "CVE-2010-2656", "CVE-2009-1477"],
    "4.2.2.2": [ "CVE-2014-9510", "CVE-2014-8886", "CVE-2014-4690", "CVE-2014-2718", "CVE-2012-2607", "CVE-2012-1328", "CVE-2010-2656", "CVE-2009-1477"],
    "4.2.2.2.1": ["CVE-2011-4783", "CVE-2011-1054", "CVE-2011-1052", "CVE-2011-1051", "CVE-2007-1666", "CVE-2005-0770"],
    "4.2.2.2.2": ["CVE-2011-4783", "CVE-2011-1054", "CVE-2011-1052", "CVE-2011-1051", "CVE-2007-1666", "CVE-2005-0770"],
    "4.2.2.3": ["CVE-2014-3428", "CVE-2014-3052", "CVE-2013-6924", "CVE-2013-6920", "CVE-2010-2363", "CVE-2009-1561"],
    "4.2.2.3.1": ["CVE-2011-4783", "CVE-2011-1054", "CVE-2011-1052", "CVE-2011-1051", "CVE-2007-1666", "CVE-2005-0770"],
    "4.2.3": ["CVE-2015-5611", "CVE-2014-2073", "CVE-2011-0725", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "4.2.4": ["CVE-2015-5611", "CVE-2014-2073", "CVE-2011-0725", "CVE-2010-2959", "CVE-2010-3874", "CVE-2010-4565"],
    "4.3": ["CVE-2015-2890", "CVE-2013-2338", "CVE-2012-3271", "CVE-2010-2025", "CVE-2009-3200"],
    "4.4": [ "CVE-2015-5611", "CVE-2014-2073","CVE-2012-2607","CVE-2007-2040", "CVE-2002-0673"],
    "4.4.1": [ "CVE-2015-5611", "CVE-2014-2073","CVE-2012-2607","CVE-2007-2040", "CVE-2002-0673"],
    "4.4.2": [ "CVE-2011-2925", "CVE-2006-5729", "CVE-2005-4763", "CVE-2001-0726"],
    "4.4.2.1": ["CVE-2011-2925", "CVE-2006-5729", "CVE-2005-4763", "CVE-2001-0726"],
    "4.4.2.2": ["CVE-2011-2925", "CVE-2006-5729", "CVE-2005-4763", "CVE-2001-0726"],
    "4.4.2.3": ["CVE-2011-2925", "CVE-2006-5729", "CVE-2005-4763", "CVE-2001-0726"]
}

id_to_cves_map_toyota = {
     "0": ["CVE-2023-29389", "CVE-2023-2773", "CVE-2022-1716", "CVE-2020-15238" , "CVE-2019-9743", "CVE-2016-9337", "CVE-2019-9743", "CVE-2018-1801"],
     "1": ["CVE-2023-28896", "CVE-2022-1955", "CVE-2022-20125", "CVE-2020-5551", "CVE-2020-5610", "CVE-2020-8142", "CVE-2019-9493", "CVE-2019-14951", "CVE-2018-18203", "CVE-2015-5611", "CVE-2014-7128", "CVE-1999-1393"],
     "1.1": ["CVE-2023-28647", "CVE-2023-28646","CVE-2023-22473", "CVE-2023-21140", "CVE-2022-1955", "CVE-2022-20125", "CVE-2022-1716", "CVE-2020-8142", "CVE-2020-0473", "CVE-2018-12891", "CVE-1999-1393"],
     "1.2": ["CVE-2023-29389", "CVE-2023-21134", "CVE-2023-20924", "CVE-2021-30702", "CVE-2020-7323", "CVE-2005-2742", "CVE-2001-0605"],
     "1.3": ["CVE-2023-1256", "CVE-2023-0846", "CVE-2022-48750", "CVE-2022-48296", "CVE-2022-45462", "CVE-2020-28973", "CVE-2020-27030", "CVE-2020-14157", "CVE-2019-9659", "CVE-2019-5213", "CVE-2015-8254"],
     "2": ["CVE-2023-28896", "CVE-2018-1170", "CVE-2010-4565", "CVE-2010-3874", "CVE-2010-2959"],
     "2.1": ["CVE-2023-28896", "CVE-2018-1170", "CVE-2010-4565", "CVE-2010-3874", "CVE-2010-2959"],
     "2.1.1": ["CVE-2023-0913", "CVE-2022-23126", "CVE-2021-46067", "CVE-2010-4565", "CVE-2010-3874", "CVE-2010-2959"],
     "2.1.2": ["CVE-2023-28896", "CVE-2023-28899", "CVE-2018-1170", "CVE-2010-4565", "CVE-2019-12797", "CVE-2018-9322", "CVE-2017-3217", "CVE-2015-2908", "CVE-2015-2907", "CVE-2015-2906"],
     "2.1.3": ["CVE-2023-2255", "CVE-2023-0575", "CVE-2022-4883", "CVE-2022-48565", "CVE-2022-47514", "CVE-2021-44147", "CVE-2020-5226", "CVE-2014-1886"],
     "2.2": ["CVE-2023-2255", "CVE-2021-37910", "CVE-2021-34740", "CVE-2020-12494", "CVE-2020-9517", "CVE-2018-1170", "CVE-2017-5026"],
     "2.2.1": ["CVE-2023-1262", "CVE-2022-46149", "CVE-2021-34740", "CVE-2021-22320", "CVE-2020-3273", "CVE-2019-15264", "CVE-2015-4205", "CVE-2015-1142857"],
     "2.2.2": ["CVE-2022-33681", "CVE-2022-22172", "CVE-2021-0293", "CVE-2020-1603", "CVE-2019-15256"],
     "2.2.3": ["CVE-2023-27582", "CVE-2021-39298",  "CVE-2020-7324", "CVE-2019-19680", "CVE-2019-1844", "CVE-2018-0419", "CVE-2016-9193"],
     "2.3": ["CVE-2020-5551", "CVE-2019-18374", "CVE-2018-15321", "CVE-2018-1164", "CVE-2005-2932"],
     "2.3.1": ["CVE-2022-23126", "CVE-2020-29440", "CVE-2020-5551", "CVE-2019-18374", "CVE-2018-15321", "CVE-2018-1164", "CVE-2005-2932"],
     "2.3.2": ["CVE-2020-5551", "CVE-2019-18374", "CVE-2018-15321", "CVE-2018-1164", "CVE-2017-16241", "CVE-2005-2932"],
     "2.3.3": ["CVE-2020-5551", "CVE-2019-18374", "CVE-2018-9318", "CVE-2018-9311", "CVE-2018-15321", "CVE-2018-1164", "CVE-2005-2932"],
     "2.4": ["CVE-2023-0264", "CVE-2023-0105", "CVE-2022-43958", "CVE-2022-39207", "CVE-2021-34646", "CVE-2020-4202", "CVE-2019-3629", "CVE-2018-1999025", "CVE-2015-6926"],
     "2.4.1": ["CVE-2023-0105", "CVE-2022-31102", "CVE-2022-27225", "CVE-2022-23610	", "CVE-2022-20866", "CVE-2022-20817", "CVE-2021-38878", "CVE-2021-33846", "CVE-2020-8434", "CVE-2019-1715", "CVE-2005-0506"],
     "2.4.1.1": ["CVE-2022-36116", "CVE-2022-35917", "CVE-2021-41028", "CVE-2021-38394", "CVE-2021-3422", "CVE-2018-15781"],
     "2.4.1.2": ["CVE-2022-45142", "CVE-2022-42960", "CVE-2021-22359", "CVE-2021-22330", "CVE-2019-8664", "CVE-2018-0256", "CVE-2015-6061", "CVE-2005-3537"],
     "2.4.1.3": ["CVE-2023-1256", "CVE-2023-0846", "CVE-2022-48750", "CVE-2022-48296", "CVE-2022-45462", "CVE-2020-28973", "CVE-2020-27030", "CVE-2020-14157", "CVE-2019-9659", "CVE-2019-5213", "CVE-2015-8254"],
     "2.4.2": ["CVE-2023-0264", "CVE-2023-0105", "CVE-2022-43958", "CVE-2022-39207", "CVE-2021-34646", "CVE-2020-4202", "CVE-2019-3629", "CVE-2018-1999025", "CVE-2015-6926"],
     "3": ["CVE-2023-0026", "CVE-2022-22184", "CVE-2021-36131", "CVE-2021-36130", "CVE-2020-3638", "CVE-2016-5406", "CVE-2015-1303"],
     "3.1": ["CVE-2023-29389", "CVE-2023-2717", "CVE-2021-21333", "CVE-2019-9155", "CVE-2006-2705", "CVE-2005-0066", "CVE-2002-1446"],
     "3.1.1": ["CVE-2023-29389", "CVE-2023-2717", "CVE-2021-21333", "CVE-2019-9155", "CVE-2006-2705", "CVE-2005-0066", "CVE-2002-1446"],
     "3.1.2": ["CVE-2023-29389", "CVE-2023-2717", "CVE-2021-21333", "CVE-2019-9155", "CVE-2006-2705", "CVE-2005-0066", "CVE-2002-1446"],
     "3.2": ["CVE-2022-35287", "CVE-2021-32781", "CVE-2020-4690", "CVE-2020-15087", "CVE-2018-1959", "CVE-2017-12342", "CVE-2012-3520"],
     "4": ["CVE-2019-6574", "CVE-2019-2576", "CVE-2018-2876", "CVE-2017-3507", "CVE-2017-10119"],
     "4.1": ["CVE-2022-39405", "CVE-2021-37531", "CVE-2021-20487", "CVE-2018-8552", "CVE-2017-8548", "CVE-2017-11834", "CVE-1999-0883"],
     "4.1.1": ["CVE-2023-0361", "CVE-2022-48021", "CVE-2022-43974", "CVE-2022-36880", "CVE-2021-32795", "CVE-2020-27283", "CVE-2019-5257", "CVE-2017-8019", "CVE-2013-1299"],
     "4.1.2": ["CVE-2023-28899", "CVE-2023-0001", "CVE-2022-48824", "CVE-2021-40837", "CVE-2020-3496", "CVE-2017-6653"],
     "4.1.3": ["CVE-2023-0221", "CVE-2022-41974", "CVE-2022-26858", "CVE-2022-22394", "CVE-2022-1955", "CVE-2021-35534", "CVE-2020-3482", "CVE-2019-0057", "CVE-2007-3570", "CVE-2005-4342"],
     "4.2": ["CVE-2023-29389", "CVE-2023-0870", "CVE-2022-46487", "CVE-2022-4137", "CVE-2022-21498", "CVE-2021-44057", "CVE-2021-35601", "CVE-2021-2414", "CVE-2018-3175", "CVE-2017-10153", "CVE-2000-0954" ],
     "4.2.1": ["CVE-2022-35924", "CVE-2022-29441", "CVE-2021-30478", "CVE-2018-15682", "CVE-2018-14062", "CVE-2014-5395", "CVE-2014-0239", "CVE-2012-5695", "CVE-2008-1172", "CVE-2006-6508"],
     "4.2.2": ["CVE-2020-9438", "CVE-2017-16241", "CVE-2017-13903", "CVE-2015-2848", "CVE-2000-0954" ],
     "4.2.3": ["CVE-2022-48941", "CVE-2020-9438", "CVE-2019-18373", "CVE-2017-16241", "CVE-2017-13903", "CVE-2015-2848", "CVE-2006-2933", "CVE-2000-0954"],
     "4.3": ["CVE-2023-29389", "CVE-2023-0870","CVE-2022-39405", "CVE-2021-37531", "CVE-2021-20487", "CVE-2018-8552", "CVE-2018-3175", "CVE-2017-10153", "CVE-2000-0954" ],
     "4.3.1": ["CVE-2022-33682", "CVE-2021-44225", "CVE-2020-15099", "CVE-2018-10192", "CVE-2017-3226", "CVE-2016-0394", "CVE-2011-1070"],
     "4.3.2": ["CVE-2022-35924", "CVE-2022-29441", "CVE-2021-30478", "CVE-2018-14062", "CVE-2014-5395", "CVE-2013-0235", "CVE-2012-5695", "CVE-2007-0622", "CVE-2006-6508"],
     "4.4": ["CVE-2013-6196", "CVE-2012-6349", "CVE-2012-6277", "CVE-2011-1218", "CVE-2010-0126", "CVE-2009-0347", "CVE-2008-1718", "CVE-2007-5405", "CVE-2005-2619"],
     "4.4.1": ["CVE-2020-26230", "CVE-2020-14946", "CVE-2020-14945", "CVE-2020-14944", "CVE-2018-6324", "CVE-2018-1000046", "CVE-2014-3062", "CVE-2013-5967"],
     "4.4.2": ["CVE-2020-26230", "CVE-2020-14946", "CVE-2020-14945", "CVE-2020-14944", "CVE-2018-6324","CVE-2017-8864", "CVE-2018-1000046", "CVE-2014-3062", "CVE-2013-5967" ],
     "4.4.3": ["CVE-2022-28217", "CVE-2022-25594", "CVE-2022-25575", "CVE-2022-2364", "CVE-2022-2363", "CVE-2021-37806", "CVE-2021-37805", "CVE-2021-27822", "CVE-2018-7800", "CVE-2017-15958"]
}

id_to_cves_map_vw = {
     "0": ["CVE-2023-34733", "CVE-2020-28656", "CVE-2020-5610","CVE-2020-5551", "CVE-2019-14951", "CVE-2018-18203", "CVE-2013-1952", "CVE-2010-3874", "CVE-2010-2959"],
     "1": ["CVE-2023-28898", "CVE-2023-28896", "CVE-2020-10282", "CVE-2020-10281", "CVE-2015-5611"],
     "1.1": ["CVE-2023-28896", "CVE-2022-1955", "CVE-2022-20125", "CVE-2020-5551", "CVE-2020-5610", "CVE-2020-8142", "CVE-2019-9493", "CVE-2019-14951", "CVE-2018-18203", "CVE-2015-5611", "CVE-2014-7128", "CVE-1999-1393"],
     "1.2": ["CVE-2023-23632", "CVE-2023-20095", "CVE-2023-1174", "CVE-2022-24119", "CVE-2022-22001", "CVE-2022-20759", "CVE-2021-44222"],
     "2": ["CVE-2023-6073", "CVE-2019-6574", "CVE-2019-2576", "CVE-2018-2876", "CVE-2017-3507", "CVE-2017-10119"],
     "2.1": ["CVE-2023-26440", "CVE-2023-26439", "CVE-2022-31105", "CVE-2018-1712", "CVE-2017-7687", "CVE-2015-5162", "CVE-2014-5087", "CVE-1999-0908"],
     "2.1.1": ["CVE-2023-20032", "CVE-2023-20024", "CVE-2023-20012", "CVE-2023-1424", "CVE-2022-46910", "CVE-2022-46423", "CVE-2022-45441", "CVE-2021-34730", "CVE-2021-3375"],
     "2.1.2": ["CVE-2023-6073", "CVE-2023-47700", "CVE-2012-0675", "CVE-2011-3462", "CVE-2010-1803" ],
     "2.2": ["CVE-2023-0221", "CVE-2022-41974", "CVE-2022-26858", "CVE-2022-22394", "CVE-2022-1955", "CVE-2021-35534", "CVE-2020-3482", "CVE-2019-0057", "CVE-2007-3570", "CVE-2005-4342"],
     "2.2.1": ["CVE-2023-22600", "CVE-2022-39946", "CVE-2022-39945", "CVE-2022-38380", "CVE-2022-38377", "CVE-2022-2792", "CVE-2021-41020", "CVE-2021-36177", "CVE-2021-26110", "CVE-2020-15939", "CVE-2019-6958", "CVE-2019-6810", "CVE-2018-7847"],
     "2.2.2": ["CVE-2023-6073", "CVE-2019-6574", "CVE-2019-2576", "CVE-2018-2876", "CVE-2017-3507", "CVE-2017-10119"]
}

class AttackTree:
    def __init__(self):
        self.nodes = {}
        self.root = None

    def fetch_cves_by_ids(self, attack_node):
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        cve_ids = id_to_cves_map_unicar_agil.get(attack_node.id, [])
        headers = {
            'apiKey': nvd_api_key
        }
        for cve_id in cve_ids:
            request_url = f"{base_url}?cveId={cve_id}"
            print(f"Requesting: {request_url}")
            try:

                response = requests.get(request_url, headers=headers, timeout=3)
                # response = requests.get(request_url)
                if response.content:
                    # Decode the byte string to a JSON string
                    json_str = response.content.decode('utf-8')
                    # Parse the JSON string into a Python dictionary
                    cve_data = json.loads(json_str)

                    # Extract the CVE object
                    cve = cve_data.get("vulnerabilities", [{}])[0].get("cve", {})

                    # Check for CVSS v3.1 or CVSS v3.0 metrics first
                    if CVSS_V31_STR in cve.get("metrics", {}):
                        cve_cvss_data = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
                        published_time = datetime.datetime.fromisoformat(cve['published']).timestamp()
                    elif CVSS_V30_STR in cve.get("metrics", {}):
                        cve_cvss_data = cve["metrics"]["cvssMetricV30"][0]["cvssData"]
                        published_time = datetime.datetime.fromisoformat(cve['published']).timestamp()
                    # Fallback to CVSS v2.0 metrics if v3.1 or v3.0 are not found
                    elif CVSS_V20_STR in cve.get("metrics", {}):
                        cve_cvss_data = cve["metrics"]["cvssMetricV2"][0]["cvssData"]
                        published_time = datetime.datetime.fromisoformat(cve['published']).timestamp()
                        av = float(Metric.AttackVector.from_str(cve_cvss_data["accessVector"].lower()).value)
                        ac = float(Metric.AccessComplexity.from_str(cve_cvss_data["accessComplexity"].lower()).value)
                        pr = 0.85
                        ui = 0.85

                        attack_node.update_histories(av, ac, pr, ui, published_time)
                        continue

                    av = float(Metric.AttackVector.from_str(cve_cvss_data["attackVector"].lower()).value)
                    ac = float(Metric.AttackComplexity.from_str(cve_cvss_data["attackComplexity"].lower()).value)
                    pr = float(Metric.PrivilegeRequired.from_str(cve_cvss_data["privilegesRequired"].lower()).value)
                    ui = float(Metric.UserInteraction.from_str(cve_cvss_data["userInteraction"].lower()).value)

                    attack_node.update_histories(av, ac, pr, ui, published_time)
                else:
                    print(f"Empty response for {cve_id}")

            except requests.exceptions.HTTPError as http_err:
                print(f"HTTP error occurred for {cve_id}: {http_err}")
            except requests.exceptions.RequestException as req_err:
                print(f"Request error occurred for {cve_id}: {req_err}")
            except ValueError as json_err:
                print(response.status_code)  # Check the status code first
                print(response.text)  # Print the response content to see if it's valid JSON
                print(f"JSON decode error for {cve_id}: {json_err}")

    def import_attack_tree_from_file(self, filename):
        with open(filename, 'r') as file:
            lines = file.readlines()

        current_node = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("ID:"):
                # Add the last node to the nodes dictionary and fetch CVEs
                """
                To calculate the aging for each attack step in the online phase, we need feasibility history.
                In our case (as the only historical feasibility is the feasibility value assigned during the initial phase), 
                then we generate the feasibility history and the cvss attributes history from the CVE dataset, by extracting
                a set of similar CVEs for each attack step.

                """
                if current_node:
                    self.nodes[current_node.id] = current_node
                    self.fetch_cves_by_ids(current_node)

                node_id = line.split(":")[1].strip()
                current_node = AttackNode(id=node_id, node_type=None, name=None, description=None, feasibility=None)

            elif line.startswith("Node type:"):
                current_node.node_type = line.split(":")[1].strip()

            elif line.startswith("Name:"):
                current_node.name = line.split(":")[1].strip()

            elif line.startswith("Description:"):
                current_node.description = line.split(":")[1].strip()

            elif line.startswith("Gate:"):
                current_node.gate = line.split(":")[1].strip()

            elif line.startswith("Parent:"):
                current_node.parent = line.split(":")[1].strip()

            elif line.startswith("AV:"):
                current_node.av = Metric.AttackVector.from_str(line.split(":")[1].strip()).value

            elif line.startswith("AC:"):
                current_node.ac = Metric.AttackComplexity.from_str(line.split(":")[1].strip()).value

            elif line.startswith("PR:"):
                current_node.pr = Metric.PrivilegeRequired.from_str(line.split(":")[1].strip()).value

            elif line.startswith("UI:"):
                current_node.ui = Metric.UserInteraction.from_str(line.split(":")[1].strip()).value

        current_node.update_histories(current_node.av,current_node.ac, current_node.pr, current_node.ui,0)
        # Assign children nodes based on the parent attribute
        for node in self.nodes.values():
            if node.parent and node.parent in self.nodes:
                parent_node = self.nodes[node.parent]
                parent_node.add_child(node)

        # Set the root node (assuming it has ID "0")
        self.root = self.nodes.get("0")

        return self.nodes
    
    def find_node_by_id(self, node_id):
        return self.nodes.get(node_id)

    # @staticmethod
    def visualize_attack_tree(self, name):
        

        dot = Digraph()

        def add_nodes_edges(node):

            # Add the current node
            dot.node(node.id, f"{node.name}")
            
            
            if node.children:
           
                # Create a unique gate node ID
                gate_node_id = f"{node.id}_gate"

                # Determine the gate type and corresponding shape
                if hasattr(node, 'gate'):
                    gate_type = node.gate
                    if gate_type == "AND":
                        shape = "record"
                    elif gate_type == "OR":
                        shape = "ellipse"
                    else:
                        shape = "diamond"  # Fallback for unknown gate types
                else:
                    gate_type = " "
                    shape = "diamond"  # Default shape if no gate_type is specified

                # Add the gate node with the appropriate shape
                dot.node(gate_node_id, label=gate_type, shape=shape)

                # Connect the parent node to the gate node
                dot.edge(node.id, gate_node_id)

                # Add edges from the gate node to each child
                for child in node.children:
                    dot.edge(gate_node_id, child.id)
                    add_nodes_edges(child)

        if self.root:
            add_nodes_edges(self.root)
        else:
            print("No root node found.")

        dot.render(f"Results/Initial_phase_results/attack_tree_{name}", format="png")
        dot.render(f"Results/Initial_phase_results/attack_tree_{name}", format="pdf")
        dot.view()

    @staticmethod
    def serialize_to_openxsam_attack_tree(attack_tree, file_path):
        def serialize_node(node):
            # Create XML element for the node
            node_element = ET.Element('AttackNode')
            
            # Add attributes and child elements
            ET.SubElement(node_element, 'ID').text = node.id
            ET.SubElement(node_element, 'NodeType').text = node.node_type
            ET.SubElement(node_element, 'Name').text = node.name
            ET.SubElement(node_element, 'Description').text = node.description
            ET.SubElement(node_element, 'Feasibility').text = str(node.feasibility)
            ET.SubElement(node_element, 'Gate').text = node.gate
            ET.SubElement(node_element, 'AV').text = str(node.av) 
            ET.SubElement(node_element, 'AC').text = str(node.ac)  
            ET.SubElement(node_element, 'PR').text = str(node.pr) 
            ET.SubElement(node_element, 'UI').text = str(node.ui)  
            ET.SubElement(node_element, 'Parent').text = node.parent if node.parent else "None"

             # Serialize feasibility history for av_history (as a comma-separated string)
            av_history = ','.join(f"({t[0]},{t[1]})" for t in node.av_history)
            ET.SubElement(node_element, 'AVHistory').text = av_history

            # Serialize feasibility history for ac_history (as a comma-separated string)
            ac_history = ','.join(f"({t[0]},{t[1]})" for t in node.ac_history)
            ET.SubElement(node_element, 'ACHistory').text = ac_history

            # Serialize feasibility history for pr_history (as a comma-separated string)
            pr_history = ','.join(f"({t[0]},{t[1]})" for t in node.pr_history)
            ET.SubElement(node_element, 'PRHistory').text = pr_history

            # Serialize feasibility history for ui_history (as a comma-separated string)
            ui_history = ','.join(f"({t[0]},{t[1]})" for t in node.ui_history)
            ET.SubElement(node_element, 'UIHistory').text = ui_history


            # Serialize children nodes
            for child in node.children:
                child_element = serialize_node(child)
                node_element.append(child_element)
            
            return node_element

        # Create the root element and serialize the tree
        root_element = ET.Element('AttackTree')
        
        if attack_tree.root:
            root_node_element = serialize_node(attack_tree.root)
            root_element.append(root_node_element)
        else:
            print("No root node found in the attack tree.")
        
        # Create the tree structure and write to file
        tree = ET.ElementTree(root_element)
        with open(file_path, 'wb') as file:
            tree.write(file, encoding='utf-8', xml_declaration=True)

    @staticmethod
    def deserialize_from_openxsam_attack_tree(file_path):
        def parse_node(node_element):
            def safe_float(value):
                """Convert a string to float, handling 'None' or invalid values."""
                try:
                    if value is not None and value.strip().lower() != 'none':
                        return float(value)
                    else:
                        return None
                except ValueError:
                    return None
            # Function to convert time string (hh:mm:ss.mmm or a float) to seconds as float
            def time_to_float(time_str):
                if ':' in time_str:  # Check if it's a time format like "hh:mm:ss.mmm"
                    h, m, s = time_str.split(':')
                    return int(h) * 3600 + int(m) * 60 + float(s)
                return float(time_str)  # Handle case where it's just a number like "0.55"

            # Updated safe_tuple function to process the string and return the tuple of floats
            def safe_tuple(tuple_str):
                # Use regex to match and extract values and time (closing parenthesis is optional)
                pattern = r'\(?([\d.]+),([\d:.]+)\)?'
                match = re.match(pattern, tuple_str)
                if match:
                    value, time = match.groups()
                    return float(value), time_to_float(time)
                return tuple()  # Return an empty tuple if the format doesn't match

            # Read attributes and create AttackNode
            node_id = node_element.find('ID').text
            node_type = node_element.find('NodeType').text
            name = node_element.find('Name').text
            description = node_element.find('Description').text
            feasibility_text = node_element.find('Feasibility').text
            gate = node_element.find('Gate').text
            x = node_element.find('AV')
            av = safe_float(node_element.find('AV').text)
            ac = safe_float(node_element.find('AC').text)
            pr = safe_float(node_element.find('PR').text)
            ui = safe_float(node_element.find('UI').text)
            parent_id = node_element.find('Parent').text if node_element.find('Parent').text != "None" else None

            # Convert text to appropriate types
            feasibility = safe_float(feasibility_text)


           # Parse av history (convert from comma-separated string to a list of tuples of floats)
            av_history_str = node_element.find('AVHistory').text
            av_history = list(map(safe_tuple, av_history_str.split('),('))) if av_history_str else []

            # Parse ac history (convert from comma-separated string to a list of tuples of floats)
            ac_history_str = node_element.find('ACHistory').text
            ac_history = list(map(safe_tuple, ac_history_str.split('),('))) if ac_history_str else []

            # Parse pr history (convert from comma-separated string to a list of tuples of floats)
            pr_history_str = node_element.find('PRHistory').text
            pr_history = list(map(safe_tuple, pr_history_str.split('),('))) if pr_history_str else []

            # Parse ui history (convert from comma-separated string to a list of tuples of floats)
            ui_history_str = node_element.find('UIHistory').text
            ui_history = list(map(safe_tuple, ui_history_str.split('),('))) if ui_history_str else []

            # Create AttackNode
            node = AttackNode(
                id=node_id, node_type=node_type, name=name, description=description,
                feasibility=feasibility, gate=gate, av=av, ac=ac, pr=pr, ui=ui, parent=parent_id, 
                av_history=av_history, ac_history=ac_history, pr_history=pr_history, ui_history=ui_history
            )
            
            # Parse and attach children
            for child_element in node_element.findall('AttackNode'):
                child_node = parse_node(child_element)
                node.children.append(child_node)
            
            return node

        # Parse the XSAM file
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Create AttackTree and populate it
        attack_tree = AttackTree()
        if root:
            root_node_element = root.find('AttackNode')
            if root_node_element is not None:
                root_node = parse_node(root_node_element)
                attack_tree.root = root_node
            else:
                print("No root node found in the attack tree file.")
        
        return attack_tree
