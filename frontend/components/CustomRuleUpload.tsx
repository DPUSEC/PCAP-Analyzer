import type { ChangeEvent } from "react"
import { apiUrl } from "@/constants"
import { useState } from "react"
export function CustomRuleUpload() {
  const [customRule, setCustomRule] = useState<File | null>(null)

  const onDelete = () => {
    setCustomRule(null)
  }

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      setCustomRule(event.target.files[0])
    }
  }

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!customRule) {
      alert("Please Select File")
      return
    }
    const formData = new FormData()
    formData.append("rules_file", customRule)
    const description = (event.target as HTMLFormElement).querySelector('textarea[name="description"]')?.value
    if (!description) {
      alert("Please enter a description")
      return
    }
    formData.append("description", description)

    fetch(apiUrl + "/rules", {
      method: "POST",
      body: formData,
      headers: {
        "Authorization": `Bearer ${localStorage.getItem("authToken")}`
      }
    })
      .then(async response => {
        if (response.ok) {
          alert("Rule loaded successfully")
          setCustomRule(null)
          window.location.reload()
        } else {
          alert("An error occurred while loading the rule")
        }
      })
      .catch(error => {
        console.error("Upload error:", error)
        alert("An error occurred while loading the rule.")
      })
  }

  return (
    <div className="space-y-4">
      <div className="border-2 border-dashed border-orange-300 rounded-lg p-6 text-center">
        {customRule ? (
          <>
            <form onSubmit={handleSubmit}>
              <div className="flex items-center justify-between bg-orange-50 p-3 rounded-md">
                <span className="text-sm text-orange-800">{customRule.name}</span>
                <div className="space-x-2">
                  <button
                    onClick={onDelete}
                    className="text-red-500 hover:text-red-700 text-sm font-medium"
                  >
                    Sil
                  </button>
                </div>
              </div>
              <textarea name="description" placeholder="Enter the description of the rule" required className="w-full border-2 border-gray-300 rounded-md p-2 mt-4 text-black" />
              <button type="submit" className="mt-2 px-4 py-2 bg-orange-500 text-black rounded-md">
                Yükle
              </button>
            </form>
          </>
        ) : (
          <>
            <label className="cursor-pointer">
              <input
                type="file"
                className="hidden"
                accept=".rules"
                onChange={handleFileChange}
              />
              <div className="space-y-2">
                <div className="text-sm text-orange-600">
                  Load Custom Suricata Rules (optional)
                </div>
                <div className="text-xs text-gray-500">
                You can upload files with .rules extension

                </div>
              </div>
            </label>
          </>
        )}
      </div>
    </div>
  )
}

