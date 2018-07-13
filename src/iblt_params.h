/*
Copyright (c) 2018 The Bitcoin Unlimited developers
Distributed under the MIT software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.

This file has been auto-generated using a template found in the 
following repository. The template was populated using data 
generated with a script that is also found in this repository.

https://github.com/umass-forensics/IBLT-optimization
*/
#include <map>

class IbltParamItem 
{
public:
	float overhead;	
	uint8_t numhashes;

	IbltParamItem(float _overhead, uint8_t _numhashes)
	{
		IbltParamItem::overhead = _overhead;
		IbltParamItem::numhashes = _numhashes;
	}

};

const IbltParamItem DEFAULT_PARAM_ITEM(1.5, 3);

class CIbltParams
{
public:
    static std::map<size_t, IbltParamItem> paramMap;
	static IbltParamItem Lookup(size_t nItems)
	{
		auto pos = CIbltParams::paramMap.find(nItems);
		
		if (pos == CIbltParams::paramMap.end())
			return DEFAULT_PARAM_ITEM;
		else 
			return pos->second;
	}	
};

std::map<size_t, IbltParamItem> CIbltParams::paramMap = {
	{1, IbltParamItem(6.000000, 3)},
	{2, IbltParamItem(7.500000, 5)},
	{3, IbltParamItem(6.666667, 5)},
	{4, IbltParamItem(5.500000, 11)},
	{5, IbltParamItem(6.000000, 5)},
	{6, IbltParamItem(4.000000, 6)},
	{7, IbltParamItem(3.857143, 9)},
	{8, IbltParamItem(3.500000, 7)},
	{9, IbltParamItem(3.333333, 6)},
	{10, IbltParamItem(3.000000, 6)},
	{11, IbltParamItem(3.181818, 5)},
	{12, IbltParamItem(2.916667, 7)},
	{13, IbltParamItem(2.692308, 7)},
	{14, IbltParamItem(2.571429, 6)},
	{15, IbltParamItem(2.666667, 5)},
	{16, IbltParamItem(2.500000, 5)},
	{17, IbltParamItem(2.470588, 6)},
	{18, IbltParamItem(2.333333, 6)},
	{19, IbltParamItem(2.368421, 5)},
	{20, IbltParamItem(2.250000, 5)},
	{21, IbltParamItem(2.285714, 6)},
	{22, IbltParamItem(2.181818, 6)},
	{23, IbltParamItem(2.173913, 5)},
	{24, IbltParamItem(2.083333, 5)},
	{25, IbltParamItem(2.160000, 6)},
	{26, IbltParamItem(2.115385, 5)},
	{27, IbltParamItem(2.037037, 5)},
	{28, IbltParamItem(2.142857, 5)},
	{29, IbltParamItem(2.068966, 5)},
	{30, IbltParamItem(2.000000, 5)},
	{31, IbltParamItem(2.096774, 5)},
	{32, IbltParamItem(2.031250, 5)},
	{33, IbltParamItem(1.969697, 5)},
	{34, IbltParamItem(1.911765, 5)},
	{35, IbltParamItem(2.000000, 5)},
	{36, IbltParamItem(1.944444, 5)},
	{37, IbltParamItem(1.891892, 5)},
	{38, IbltParamItem(1.973684, 5)},
	{39, IbltParamItem(1.923077, 5)},
	{40, IbltParamItem(1.875000, 5)},
	{41, IbltParamItem(2.048780, 6)},
	{42, IbltParamItem(1.904762, 5)},
	{43, IbltParamItem(1.860465, 5)},
	{44, IbltParamItem(1.818182, 5)},
	{45, IbltParamItem(1.888889, 5)},
	{46, IbltParamItem(1.847826, 5)},
	{47, IbltParamItem(1.808511, 5)},
	{48, IbltParamItem(1.979167, 5)},
	{49, IbltParamItem(1.795918, 4)},
	{50, IbltParamItem(1.800000, 5)},
	{51, IbltParamItem(1.960784, 4)},
	{52, IbltParamItem(1.826923, 5)},
	{53, IbltParamItem(1.792453, 5)},
	{54, IbltParamItem(1.777778, 4)},
	{55, IbltParamItem(1.745455, 4)},
	{56, IbltParamItem(1.785714, 4)},
	{57, IbltParamItem(1.754386, 4)},
	{58, IbltParamItem(1.793103, 4)},
	{59, IbltParamItem(1.762712, 4)},
	{60, IbltParamItem(1.733333, 4)},
	{61, IbltParamItem(1.770492, 4)},
	{62, IbltParamItem(1.741935, 4)},
	{63, IbltParamItem(1.746032, 5)},
	{65, IbltParamItem(1.723077, 4)},
	{66, IbltParamItem(1.696970, 4)},
	{67, IbltParamItem(1.731343, 4)},
	{68, IbltParamItem(1.705882, 4)},
	{69, IbltParamItem(1.681159, 4)},
	{70, IbltParamItem(1.714286, 4)},
	{71, IbltParamItem(1.690141, 4)},
	{72, IbltParamItem(1.722222, 4)},
	{73, IbltParamItem(1.698630, 4)},
	{74, IbltParamItem(1.675676, 4)},
	{75, IbltParamItem(1.706667, 4)},
	{76, IbltParamItem(1.684211, 4)},
	{77, IbltParamItem(1.610390, 4)},
	{78, IbltParamItem(1.692308, 4)},
	{79, IbltParamItem(1.670886, 4)},
	{80, IbltParamItem(1.600000, 4)},
	{81, IbltParamItem(1.679012, 4)},
	{82, IbltParamItem(1.609756, 4)},
	{83, IbltParamItem(1.590361, 4)},
	{84, IbltParamItem(1.571429, 4)},
	{85, IbltParamItem(1.600000, 4)},
	{86, IbltParamItem(1.581395, 4)},
	{87, IbltParamItem(1.655172, 4)},
	{88, IbltParamItem(1.590909, 4)},
	{89, IbltParamItem(1.573034, 4)},
	{90, IbltParamItem(1.600000, 4)},
	{91, IbltParamItem(1.582418, 4)},
	{92, IbltParamItem(1.565217, 4)},
	{93, IbltParamItem(1.591398, 4)},
	{94, IbltParamItem(1.574468, 4)},
	{95, IbltParamItem(1.600000, 4)},
	{96, IbltParamItem(1.583333, 4)},
	{97, IbltParamItem(1.567010, 4)},
	{98, IbltParamItem(1.591837, 4)},
	{99, IbltParamItem(1.575758, 4)},
	{100, IbltParamItem(1.600000, 4)},
	{101, IbltParamItem(1.584158, 4)},
	{102, IbltParamItem(1.568627, 4)},
	{103, IbltParamItem(1.592233, 4)},
	{104, IbltParamItem(1.576923, 4)},
	{105, IbltParamItem(1.600000, 4)},
	{106, IbltParamItem(1.584906, 4)},
	{107, IbltParamItem(1.570093, 4)},
	{108, IbltParamItem(1.592593, 4)},
	{109, IbltParamItem(1.577982, 4)},
	{110, IbltParamItem(1.563636, 4)},
	{111, IbltParamItem(1.585586, 4)},
	{112, IbltParamItem(1.571429, 4)},
	{113, IbltParamItem(1.592920, 4)},
	{114, IbltParamItem(1.578947, 4)},
	{115, IbltParamItem(1.565217, 4)},
	{116, IbltParamItem(1.517241, 4)},
	{117, IbltParamItem(1.572650, 4)},
	{118, IbltParamItem(1.525424, 4)},
	{119, IbltParamItem(1.579832, 4)},
	{120, IbltParamItem(1.566667, 4)},
	{121, IbltParamItem(1.553719, 4)},
	{122, IbltParamItem(1.540984, 4)},
	{123, IbltParamItem(1.560976, 4)},
	{124, IbltParamItem(1.548387, 4)},
	{125, IbltParamItem(1.536000, 4)},
	{126, IbltParamItem(1.555556, 4)},
	{127, IbltParamItem(1.543307, 4)},
	{128, IbltParamItem(1.531250, 4)},
	{129, IbltParamItem(1.550388, 4)},
	{130, IbltParamItem(1.538462, 4)},
	{131, IbltParamItem(1.496183, 4)},
	{132, IbltParamItem(1.545455, 4)},
	{133, IbltParamItem(1.533835, 4)},
	{134, IbltParamItem(1.552239, 4)},
	{135, IbltParamItem(1.540741, 4)},
	{136, IbltParamItem(1.500000, 4)},
	{137, IbltParamItem(1.547445, 4)},
	{138, IbltParamItem(1.536232, 4)},
	{139, IbltParamItem(1.496403, 4)},
	{140, IbltParamItem(1.542857, 4)},
	{141, IbltParamItem(1.503546, 4)},
	{142, IbltParamItem(1.492958, 4)},
	{143, IbltParamItem(1.538462, 4)},
	{144, IbltParamItem(1.500000, 4)},
	{145, IbltParamItem(1.489655, 4)},
	{146, IbltParamItem(1.506849, 4)},
	{147, IbltParamItem(1.496599, 4)},
	{148, IbltParamItem(1.486486, 4)},
	{149, IbltParamItem(1.503356, 4)},
	{150, IbltParamItem(1.493333, 4)},
	{151, IbltParamItem(1.483444, 4)},
	{152, IbltParamItem(1.500000, 4)},
	{153, IbltParamItem(1.490196, 4)},
	{154, IbltParamItem(1.506494, 4)},
	{155, IbltParamItem(1.496774, 4)},
	{156, IbltParamItem(1.487179, 4)},
	{157, IbltParamItem(1.503185, 4)},
	{158, IbltParamItem(1.493671, 4)},
	{159, IbltParamItem(1.509434, 4)},
	{160, IbltParamItem(1.500000, 4)},
	{161, IbltParamItem(1.490683, 4)},
	{162, IbltParamItem(1.481481, 4)},
	{163, IbltParamItem(1.472393, 4)},
	{164, IbltParamItem(1.487805, 4)},
	{165, IbltParamItem(1.478788, 4)},
	{166, IbltParamItem(1.469880, 4)},
	{167, IbltParamItem(1.485030, 4)},
	{168, IbltParamItem(1.476190, 4)},
	{169, IbltParamItem(1.491124, 4)},
	{170, IbltParamItem(1.482353, 4)},
	{171, IbltParamItem(1.473684, 4)},
	{172, IbltParamItem(1.488372, 4)},
	{173, IbltParamItem(1.479769, 4)},
	{174, IbltParamItem(1.471264, 4)},
	{175, IbltParamItem(1.485714, 4)},
	{176, IbltParamItem(1.477273, 4)},
	{177, IbltParamItem(1.491525, 4)},
	{178, IbltParamItem(1.483146, 4)},
	{179, IbltParamItem(1.474860, 4)},
	{180, IbltParamItem(1.488889, 4)},
	{181, IbltParamItem(1.480663, 4)},
	{182, IbltParamItem(1.494505, 4)},
	{183, IbltParamItem(1.486339, 4)},
	{184, IbltParamItem(1.478261, 4)},
	{185, IbltParamItem(1.491892, 4)},
	{186, IbltParamItem(1.483871, 4)},
	{187, IbltParamItem(1.454545, 4)},
	{188, IbltParamItem(1.489362, 4)},
	{189, IbltParamItem(1.481481, 4)},
	{190, IbltParamItem(1.494737, 4)},
	{191, IbltParamItem(1.486911, 4)},
	{192, IbltParamItem(1.479167, 4)},
	{193, IbltParamItem(1.492228, 4)},
	{194, IbltParamItem(1.484536, 4)},
	{195, IbltParamItem(1.456410, 4)},
	{196, IbltParamItem(1.489796, 4)},
	{197, IbltParamItem(1.482234, 4)},
	{198, IbltParamItem(1.454545, 4)},
	{200, IbltParamItem(1.460000, 4)},
	{201, IbltParamItem(1.452736, 4)},
	{202, IbltParamItem(1.485149, 4)},
	{203, IbltParamItem(1.477833, 4)},
	{204, IbltParamItem(1.470588, 4)},
	{205, IbltParamItem(1.482927, 4)},
	{206, IbltParamItem(1.475728, 4)},
	{207, IbltParamItem(1.468599, 4)},
	{208, IbltParamItem(1.480769, 4)},
	{210, IbltParamItem(1.485714, 4)},
	{211, IbltParamItem(1.478673, 4)},
	{212, IbltParamItem(1.471698, 4)},
	{213, IbltParamItem(1.446009, 4)},
	{214, IbltParamItem(1.476636, 4)},
	{215, IbltParamItem(1.469767, 4)},
	{216, IbltParamItem(1.481481, 4)},
	{217, IbltParamItem(1.474654, 4)},
	{218, IbltParamItem(1.449541, 4)},
	{219, IbltParamItem(1.442922, 4)},
	{220, IbltParamItem(1.472727, 4)},
	{221, IbltParamItem(1.447964, 4)},
	{222, IbltParamItem(1.441441, 4)},
	{223, IbltParamItem(1.470852, 4)},
	{224, IbltParamItem(1.464286, 4)},
	{225, IbltParamItem(1.457778, 4)},
	{226, IbltParamItem(1.469027, 4)},
	{227, IbltParamItem(1.462555, 4)},
	{228, IbltParamItem(1.438596, 4)},
	{229, IbltParamItem(1.467249, 4)},
	{230, IbltParamItem(1.460870, 4)},
	{231, IbltParamItem(1.437229, 4)},
	{232, IbltParamItem(1.465517, 4)},
	{233, IbltParamItem(1.442060, 4)},
	{234, IbltParamItem(1.470085, 4)},
	{235, IbltParamItem(1.463830, 4)},
	{236, IbltParamItem(1.440678, 4)},
	{237, IbltParamItem(1.468354, 4)},
	{238, IbltParamItem(1.462185, 4)},
	{239, IbltParamItem(1.439331, 4)},
	{240, IbltParamItem(1.433333, 4)},
	{241, IbltParamItem(1.443983, 4)},
	{242, IbltParamItem(1.438017, 4)},
	{243, IbltParamItem(1.465021, 4)},
	{244, IbltParamItem(1.459016, 4)},
	{245, IbltParamItem(1.453061, 4)},
	{246, IbltParamItem(1.430894, 4)},
	{247, IbltParamItem(1.457490, 4)},
	{248, IbltParamItem(1.451613, 4)},
	{249, IbltParamItem(1.429719, 4)},
	{250, IbltParamItem(1.456000, 4)},
	{251, IbltParamItem(1.434263, 4)},
	{252, IbltParamItem(1.460317, 4)},
	{253, IbltParamItem(1.454545, 4)},
	{254, IbltParamItem(1.433071, 4)},
	{255, IbltParamItem(1.427451, 4)},
	{256, IbltParamItem(1.453125, 4)},
	{257, IbltParamItem(1.431907, 4)},
	{258, IbltParamItem(1.457364, 4)},
	{259, IbltParamItem(1.436293, 4)},
	{260, IbltParamItem(1.430769, 4)},
	{261, IbltParamItem(1.455939, 4)},
	{262, IbltParamItem(1.435115, 4)},
	{263, IbltParamItem(1.429658, 4)},
	{264, IbltParamItem(1.439394, 4)},
	{265, IbltParamItem(1.433962, 4)},
	{266, IbltParamItem(1.428571, 4)},
	{267, IbltParamItem(1.438202, 4)},
	{268, IbltParamItem(1.432836, 4)},
	{269, IbltParamItem(1.442379, 4)},
	{270, IbltParamItem(1.437037, 4)},
	{271, IbltParamItem(1.431734, 4)},
	{272, IbltParamItem(1.441176, 4)},
	{273, IbltParamItem(1.435897, 4)},
	{274, IbltParamItem(1.445255, 4)},
	{275, IbltParamItem(1.440000, 4)},
	{276, IbltParamItem(1.434783, 4)},
	{277, IbltParamItem(1.444043, 4)},
	{278, IbltParamItem(1.438849, 4)},
	{279, IbltParamItem(1.433692, 4)},
	{280, IbltParamItem(1.442857, 4)},
	{281, IbltParamItem(1.437722, 4)},
	{282, IbltParamItem(1.446809, 4)},
	{283, IbltParamItem(1.441696, 4)},
	{284, IbltParamItem(1.436620, 4)},
	{285, IbltParamItem(1.431579, 4)},
	{286, IbltParamItem(1.426573, 4)},
	{287, IbltParamItem(1.435540, 4)},
	{288, IbltParamItem(1.430556, 4)},
	{289, IbltParamItem(1.425606, 4)},
	{290, IbltParamItem(1.434483, 4)},
	{291, IbltParamItem(1.429553, 4)},
	{292, IbltParamItem(1.438356, 4)},
	{293, IbltParamItem(1.433447, 4)},
	{294, IbltParamItem(1.428571, 4)},
	{295, IbltParamItem(1.437288, 4)},
	{296, IbltParamItem(1.432432, 4)},
	{297, IbltParamItem(1.441077, 4)},
	{298, IbltParamItem(1.436242, 4)},
	{299, IbltParamItem(1.431438, 4)},
	{300, IbltParamItem(1.440000, 4)},
	{301, IbltParamItem(1.435216, 4)},
	{302, IbltParamItem(1.430464, 4)},
	{303, IbltParamItem(1.438944, 4)},
	{304, IbltParamItem(1.434211, 4)},
	{305, IbltParamItem(1.429508, 4)},
	{306, IbltParamItem(1.424837, 4)},
	{307, IbltParamItem(1.420195, 4)},
	{308, IbltParamItem(1.428571, 4)},
	{309, IbltParamItem(1.423948, 4)},
	{310, IbltParamItem(1.432258, 4)},
	{311, IbltParamItem(1.427653, 4)},
	{312, IbltParamItem(1.423077, 4)},
	{313, IbltParamItem(1.431310, 4)},
	{314, IbltParamItem(1.426752, 4)},
	{315, IbltParamItem(1.434921, 4)},
	{316, IbltParamItem(1.430380, 4)},
	{317, IbltParamItem(1.425868, 4)},
	{318, IbltParamItem(1.433962, 4)},
	{319, IbltParamItem(1.429467, 4)},
	{320, IbltParamItem(1.425000, 4)},
	{321, IbltParamItem(1.433022, 4)},
	{322, IbltParamItem(1.428571, 4)},
	{323, IbltParamItem(1.411765, 4)},
	{324, IbltParamItem(1.432099, 4)},
	{325, IbltParamItem(1.427692, 4)},
	{326, IbltParamItem(1.423313, 4)},
	{327, IbltParamItem(1.418960, 4)},
	{328, IbltParamItem(1.426829, 4)},
	{329, IbltParamItem(1.422492, 4)},
	{330, IbltParamItem(1.418182, 4)},
	{332, IbltParamItem(1.421687, 4)},
	{333, IbltParamItem(1.429429, 4)},
	{334, IbltParamItem(1.425150, 4)},
	{335, IbltParamItem(1.420896, 4)},
	{336, IbltParamItem(1.428571, 4)},
	{337, IbltParamItem(1.424332, 4)},
	{338, IbltParamItem(1.408284, 4)},
	{339, IbltParamItem(1.427729, 4)},
	{340, IbltParamItem(1.423529, 4)},
	{341, IbltParamItem(1.407625, 4)},
	{342, IbltParamItem(1.426901, 4)},
	{343, IbltParamItem(1.422741, 4)},
	{344, IbltParamItem(1.406977, 4)},
	{345, IbltParamItem(1.426087, 4)},
	{346, IbltParamItem(1.410405, 4)},
	{347, IbltParamItem(1.406340, 4)},
	{348, IbltParamItem(1.425287, 4)},
	{349, IbltParamItem(1.409742, 4)},
	{350, IbltParamItem(1.405714, 4)},
	{351, IbltParamItem(1.413105, 4)},
	{352, IbltParamItem(1.409091, 4)},
	{353, IbltParamItem(1.405099, 4)},
	{354, IbltParamItem(1.412429, 4)},
	{355, IbltParamItem(1.408451, 4)},
	{356, IbltParamItem(1.404494, 4)},
	{357, IbltParamItem(1.411765, 4)},
	{358, IbltParamItem(1.407821, 4)},
	{359, IbltParamItem(1.403900, 4)},
	{360, IbltParamItem(1.411111, 4)},
	{361, IbltParamItem(1.407202, 4)},
	{362, IbltParamItem(1.403315, 4)},
	{363, IbltParamItem(1.410468, 4)},
	{364, IbltParamItem(1.406593, 4)},
	{365, IbltParamItem(1.402740, 4)},
	{366, IbltParamItem(1.409836, 4)},
	{367, IbltParamItem(1.405995, 4)},
	{368, IbltParamItem(1.402174, 4)},
	{369, IbltParamItem(1.409214, 4)},
	{370, IbltParamItem(1.405405, 4)},
	{371, IbltParamItem(1.423181, 4)},
	{372, IbltParamItem(1.408602, 4)},
	{373, IbltParamItem(1.404826, 4)},
	{374, IbltParamItem(1.411765, 4)},
	{375, IbltParamItem(1.408000, 4)},
	{376, IbltParamItem(1.404255, 4)},
	{377, IbltParamItem(1.411141, 4)},
	{378, IbltParamItem(1.407407, 4)},
	{379, IbltParamItem(1.403694, 4)},
	{380, IbltParamItem(1.410526, 4)},
	{381, IbltParamItem(1.406824, 4)},
	{382, IbltParamItem(1.403141, 4)},
	{383, IbltParamItem(1.399478, 4)},
	{384, IbltParamItem(1.406250, 4)},
	{385, IbltParamItem(1.402597, 4)},
	{386, IbltParamItem(1.398964, 4)},
	{387, IbltParamItem(1.405685, 4)},
	{388, IbltParamItem(1.402062, 4)},
	{390, IbltParamItem(1.405128, 4)},
	{391, IbltParamItem(1.401535, 4)},
	{392, IbltParamItem(1.408163, 4)},
	{393, IbltParamItem(1.404580, 4)},
	{394, IbltParamItem(1.401015, 4)},
	{395, IbltParamItem(1.407595, 4)},
	{396, IbltParamItem(1.404040, 4)},
	{397, IbltParamItem(1.400504, 4)},
	{398, IbltParamItem(1.396985, 4)},
	{399, IbltParamItem(1.403509, 4)},
	{400, IbltParamItem(1.400000, 4)},
	{401, IbltParamItem(1.406484, 4)},
	{402, IbltParamItem(1.402985, 4)},
	{403, IbltParamItem(1.399504, 4)},
	{404, IbltParamItem(1.396040, 4)},
	{405, IbltParamItem(1.402469, 4)},
	{406, IbltParamItem(1.399015, 4)},
	{407, IbltParamItem(1.405405, 4)},
	{408, IbltParamItem(1.401961, 4)},
	{409, IbltParamItem(1.398533, 4)},
	{410, IbltParamItem(1.395122, 4)},
	{411, IbltParamItem(1.401460, 4)},
	{412, IbltParamItem(1.417476, 4)},
	{413, IbltParamItem(1.404358, 4)},
	{414, IbltParamItem(1.400966, 4)},
	{415, IbltParamItem(1.397590, 4)},
	{416, IbltParamItem(1.403846, 4)},
	{417, IbltParamItem(1.400480, 4)},
	{418, IbltParamItem(1.397129, 4)},
	{419, IbltParamItem(1.403341, 4)},
	{420, IbltParamItem(1.400000, 4)},
	{421, IbltParamItem(1.396675, 4)},
	{422, IbltParamItem(1.402844, 4)},
	{423, IbltParamItem(1.399527, 4)},
	{424, IbltParamItem(1.396226, 4)},
	{425, IbltParamItem(1.402353, 4)},
	{426, IbltParamItem(1.399061, 4)},
	{427, IbltParamItem(1.395785, 4)},
	{428, IbltParamItem(1.392523, 4)},
	{429, IbltParamItem(1.398601, 4)},
	{430, IbltParamItem(1.395349, 4)},
	{431, IbltParamItem(1.401392, 4)},
	{432, IbltParamItem(1.398148, 4)},
	{433, IbltParamItem(1.394919, 4)},
	{434, IbltParamItem(1.400922, 4)},
	{435, IbltParamItem(1.397701, 4)},
	{436, IbltParamItem(1.394495, 4)},
	{437, IbltParamItem(1.400458, 4)},
	{438, IbltParamItem(1.397260, 4)},
	{439, IbltParamItem(1.394077, 4)},
	{440, IbltParamItem(1.390909, 4)},
	{441, IbltParamItem(1.396825, 4)},
	{442, IbltParamItem(1.393665, 4)},
	{443, IbltParamItem(1.399549, 4)},
	{444, IbltParamItem(1.396396, 4)},
	{445, IbltParamItem(1.393258, 4)},
	{446, IbltParamItem(1.399103, 4)},
	{447, IbltParamItem(1.395973, 4)},
	{448, IbltParamItem(1.392857, 4)},
	{449, IbltParamItem(1.398664, 4)},
	{450, IbltParamItem(1.395556, 4)},
	{451, IbltParamItem(1.392461, 4)},
	{452, IbltParamItem(1.398230, 4)},
	{453, IbltParamItem(1.395143, 4)},
	{454, IbltParamItem(1.392070, 4)},
	{455, IbltParamItem(1.397802, 4)},
	{456, IbltParamItem(1.394737, 4)},
	{457, IbltParamItem(1.391685, 4)},
	{458, IbltParamItem(1.397380, 4)},
	{459, IbltParamItem(1.394336, 4)},
	{460, IbltParamItem(1.391304, 4)},
	{461, IbltParamItem(1.396963, 4)},
	{462, IbltParamItem(1.393939, 4)},
	{463, IbltParamItem(1.399568, 4)},
	{464, IbltParamItem(1.396552, 4)},
	{465, IbltParamItem(1.393548, 4)},
	{466, IbltParamItem(1.399142, 4)},
	{467, IbltParamItem(1.396146, 4)},
	{468, IbltParamItem(1.393162, 4)},
	{469, IbltParamItem(1.390192, 4)},
	{470, IbltParamItem(1.395745, 4)},
	{471, IbltParamItem(1.392781, 4)},
	{472, IbltParamItem(1.398305, 4)},
	{473, IbltParamItem(1.395349, 4)},
	{474, IbltParamItem(1.392405, 4)},
	{475, IbltParamItem(1.397895, 4)},
	{476, IbltParamItem(1.394958, 4)},
	{477, IbltParamItem(1.392034, 4)},
	{478, IbltParamItem(1.389121, 4)},
	{479, IbltParamItem(1.394572, 4)},
	{480, IbltParamItem(1.391667, 4)},
	{481, IbltParamItem(1.388773, 4)},
	{482, IbltParamItem(1.394191, 4)},
	{483, IbltParamItem(1.391304, 4)},
	{484, IbltParamItem(1.396694, 4)},
	{485, IbltParamItem(1.393814, 4)},
	{486, IbltParamItem(1.390947, 4)},
	{487, IbltParamItem(1.396304, 4)},
	{488, IbltParamItem(1.393443, 4)},
	{489, IbltParamItem(1.390593, 4)},
	{490, IbltParamItem(1.387755, 4)},
	{491, IbltParamItem(1.384929, 4)},
	{492, IbltParamItem(1.390244, 4)},
	{493, IbltParamItem(1.387424, 4)},
	{494, IbltParamItem(1.392713, 4)},
	{495, IbltParamItem(1.389899, 4)},
	{496, IbltParamItem(1.387097, 4)},
	{497, IbltParamItem(1.392354, 4)},
	{498, IbltParamItem(1.389558, 4)},
	{499, IbltParamItem(1.386774, 4)},
	{500, IbltParamItem(1.392000, 4)},
};
