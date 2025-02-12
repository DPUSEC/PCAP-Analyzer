import { useState, useEffect } from "react"
import { Shield, ChevronDown, ChevronRight } from "lucide-react"
import { useRouter } from 'next/navigation'
import LoadingComponent from "./LoadingComponent"
import { apiUrl } from "@/constants"

interface RuleSelectionProps {
  selectedRules: Array<string>
  setSelectedRules: (rules: Array<string>) => void
}

export function RuleSelection({ selectedRules, setSelectedRules }: RuleSelectionProps) {
  const [expandedCategories, setExpandedCategories] = useState<{ [key: string]: boolean }>({
    "Default Rule Sets": true,
  })
  const [ruleSets, setRuleSets] = useState<any[]>([])
  const router = useRouter()

  useEffect(() => {
    fetch(apiUrl + "/rules", {
      headers: {
        "Authorization": `Bearer ${localStorage.getItem("authToken")}`
      }
    })
      .then(async (response) => {
        if (response.status === 200) {
          const data = await response.json()
          let tempData = {
            name: "Rule Sets",
            rules: data.Rules,
          }
          if (!ruleSets.some(category => category.name === "Rule Sets")) {
            setRuleSets(prev => [...prev, tempData]);
          }
        }
      })
    // if (selectedRules.length === 0) {
    //   const defaultRules = ruleSets
    //     .find(category => category.ID === "67a2093317cf863e90da5799")
    //     ?.rules.map((rule: any) => rule.ID) || []
    //   setSelectedRules(defaultRules)
    // }

  }, [])

  const handleRuleToggle = (ruleId: string) => {
    if (selectedRules.some(r => r === ruleId)) {
      setSelectedRules(prev => prev.filter((r) => r !== ruleId))
    } else {
      setSelectedRules(prev => [...prev, ruleId])
    }
  }

  const toggleCategory = (categoryName: string) => {
    setExpandedCategories((prev) => ({
      ...prev,
      [categoryName]: !prev[categoryName],
    }))
  }

  const handleAnalyze = () => {
    // Diğer analiz işlemleri...
    router.push('/analysis') // Yönlendirme ekliyoruz
  }

  const handleRemoveRule = async (ruleId: string) => {
    // Sunucuya silme isteği gönder
    try {
      const response = await fetch(`${apiUrl}/rules/${ruleId}`, {
        method: 'DELETE',
        headers: {
          "Authorization": `Bearer ${localStorage.getItem("authToken")}`
        }
      });

      if (response.ok) {
        // Sadece harici kural setlerinden kaldırma işlemi
        const updatedRuleSets = ruleSets.map(category => {
          if (category.name === "Rule Sets") {
            return {
              ...category,
              rules: category.rules.filter(r => r.ID !== ruleId),
            };
          }
          return category;
        });

        setSelectedRules(selectedRules.filter(r => r !== ruleId));
        setRuleSets(updatedRuleSets); // Güncellenmiş kural setlerini ayarla
      } else if (response.status === 403) {
        alert("Bu işlemi yapmaya yetkiniz yok.");
      } else {
        alert("Kural silinirken bir hata oluştu.");
        console.error("Kural silinirken bir hata oluştu.");
      }
    } catch (error) {
      console.error("Silme işlemi sırasında bir hata oluştu:", error);
    }
  }

  return (
    <div className="py-8 text-base leading-6 space-y-4 text-gray-700 sm:text-lg sm:leading-7">
      <div className="flex items-center space-x-2">
        <Shield className="w-6 h-6 text-orange-500" />
        <span className="font-bold">Select Rule Sets</span>
      </div>
      <div className="space-y-4">
        {ruleSets.map((category) => (
          <div key={category.name} className="space-y-2">
            <h3 className="font-medium cursor-pointer flex items-center" onClick={() => toggleCategory(category.name)}>
              {expandedCategories[category.name] ? (
                <ChevronDown className="w-4 h-4 mr-2 transition-transform duration-200" />
              ) : (
                <ChevronRight className="w-4 h-4 mr-2 transition-transform duration-200" />
              )}
              {category.name}
            </h3>
            <div className={`space-y-2 ml-6 transition-all duration-200 ${expandedCategories[category.name] ? 'h-auto opacity-100' : 'h-0 opacity-0 overflow-hidden'
              }`}>
              {category.rules.map((rule: any) => (
                <div key={rule.ID} className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    checked={selectedRules.some(r => r === rule.ID)}
                    onChange={() => handleRuleToggle(rule.ID)}
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <label className="font-medium">{rule.Name}</label>
                    <p className="text-xs text-gray-500">{rule.Description}</p>
                  </div>
                  {category.name === "Rule Sets" && ( // Sadece harici kural setleri için göster
                    <button
                      onClick={() => handleRemoveRule(rule.ID)}
                      className="text-red-500 hover:text-red-700"
                    >
                      &times;
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

