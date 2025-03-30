import React, { useState, useEffect } from "react"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Bar } from "react-chartjs-2"
import { Info, FileText, Lock } from "lucide-react"
import { marked } from "marked"

const CodeVisualization = ({ responseData, membership }) => {
	const [activeTab, setActiveTab] = useState("metrics")
	const [summary, setSummary] = useState(null)
	const [isSummaryLoading, setIsSummaryLoading] = useState(false)

	// Dummy summary text for non-members
	const dummySummary = `# Code Analysis Summary

This codebase consists of multiple components with varying responsibilities and relationships. The main structure appears to follow good software engineering practices overall.

## Key Findings:
- Core functionality is well-organized into modular components
- Documentation coverage could be improved in several areas
- Some classes may benefit from further refactoring to reduce complexity
- Test coverage appears adequate for critical paths

## Recommendations:
- Consider breaking down larger classes, particularly in the service layer
- Add additional documentation to improve maintainability
- Review exception handling patterns for consistency
- Implement additional validation for edge cases`

	// Function to generate summary
	const generateSummary = async () => {
		if (summary !== null) return // Only generate once
		if (membership < 3) return // Don't generate for non-members

		setIsSummaryLoading(true)
		try {
			const response = await fetch(
				"http://localhost:5000/generateSummary",
				{
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
					body: JSON.stringify({ ucl: responseData.text }),
				}
			)

			if (!response.ok) {
				throw new Error("Failed to generate summary")
			}

			const data = await response.json()
			setSummary(data.text)
		} catch (error) {
			console.error("Error generating summary:", error)
			setSummary("Failed to generate summary. Please try again later.")
		} finally {
			setIsSummaryLoading(false)
		}
	}

	// When summary tab is selected, trigger summary generation
	useEffect(() => {
		if (activeTab === "summary" && membership >= 3) {
			generateSummary()
		}
	}, [activeTab])

	if (!responseData) {
		return (
			<div className="flex items-center justify-center h-full">
				<div className="bg-white p-6 rounded-lg shadow-md text-gray-800 text-lg font-medium">
					<div className="flex items-center">
						<div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500 mr-3"></div>
						Loading visualization...
					</div>
				</div>
			</div>
		)
	}

	// Generate chart data for metrics - add null checks
	const chartData = responseData?.metrics && {
		labels: ["Imports", "Functions", "Classes", "Methods", "Calls"],
		datasets: [
			{
				label: "Code Metrics",
				data: [
					responseData.metrics.total_imports || 0,
					responseData.metrics.total_functions || 0,
					responseData.metrics.total_classes || 0,
					responseData.metrics.total_class_methods || 0,
					responseData.metrics.total_method_calls || 0,
				],
				backgroundColor: [
					"#7F5AF0",
					"#2CB67D",
					"#FFD700",
					"#FF6B6B",
					"#4CC9F0",
				],
			},
		],
	}

	// Calculate additional metrics with null checks
	const complexityMetrics = responseData && {
		avgMethodsPerClass:
			responseData.classes &&
			responseData.classes.length > 0 &&
			responseData.metrics &&
			responseData.metrics.total_class_methods
				? (
						responseData.metrics.total_class_methods /
						responseData.classes.length
				  ).toFixed(2)
				: "0",
		avgCallsPerFunction:
			responseData.functions &&
			responseData.functions.length > 0 &&
			responseData.metrics &&
			responseData.metrics.total_method_calls
				? (
						responseData.metrics.total_method_calls /
						((responseData.functions.length || 0) +
							(responseData.metrics.total_class_methods || 0))
				  ).toFixed(2)
				: "0",
		docCoverage:
			responseData.functions && responseData.functions.length > 0
				? (
						(responseData.functions.filter(
							(f) => f.docstring && f.docstring.length > 0
						).length /
							responseData.functions.length) *
						100
				  ).toFixed(2)
				: "0",
	}

	return (
		<Card className="h-full">
			<CardHeader className="pb-2">
				<CardTitle className="text-white">
					Codebase Health Dashboard
				</CardTitle>
			</CardHeader>
			<CardContent className="p-2">
				<Tabs
					value={activeTab}
					onValueChange={setActiveTab}
					className="w-full"
				>
					<TabsList className="mb-2 text-white">
						<TabsTrigger value="metrics">Metrics</TabsTrigger>
						<TabsTrigger value="complexity">Complexity</TabsTrigger>
						<TabsTrigger value="summary">
							<FileText className="w-4 h-4 mr-1" />
							Summary
						</TabsTrigger>
					</TabsList>

					<TabsContent value="metrics" className="m-0">
						<div className="h-96 relative">
							{membership >= 3 ? (
								chartData ? (
									<Bar
										data={chartData}
										options={{
											responsive: true,
											maintainAspectRatio: false,
											plugins: {
												legend: { display: false },
												tooltip: {
													callbacks: {
														label: function (
															context
														) {
															return `Count: ${context.raw}`
														},
													},
												},
											},
											scales: {
												y: {
													beginAtZero: true,
													title: {
														display: true,
														text: "Count",
													},
												},
											},
										}}
									/>
								) : (
									<div className="flex items-center justify-center h-full">
										<p className="text-lg text-gray-700 bg-gray-100 p-4 rounded-lg shadow">
											No metric data available
										</p>
									</div>
								)
							) : (
								<>
									<div
										className="h-full"
										style={{ filter: "blur(4px)" }}
									>
										{chartData && (
											<Bar
												data={chartData}
												options={{
													responsive: true,
													maintainAspectRatio: false,
													plugins: {
														legend: {
															display: false,
														},
													},
													scales: {
														y: {
															beginAtZero: true,
															title: {
																display: true,
																text: "Count",
															},
														},
													},
												}}
											/>
										)}
									</div>
									<div className="absolute inset-0 flex items-center justify-center">
										<div className="bg-black bg-opacity-70 p-4 rounded-lg text-white">
											<Lock
												className="inline mr-2"
												size={20}
											/>
											Upgrade to Plus to access code
											metrics
										</div>
									</div>
								</>
							)}
						</div>
					</TabsContent>

					<TabsContent value="complexity" className="m-0 text-white">
						<div className="h-96 relative">
							{membership >= 3 ? (
								complexityMetrics ? (
									<div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
										<Card>
											<CardHeader className="pb-2">
												<CardTitle className="text-base">
													Avg Methods Per Class
												</CardTitle>
											</CardHeader>
											<CardContent>
												<div className="text-3xl font-bold text-center">
													{
														complexityMetrics.avgMethodsPerClass
													}
												</div>
												<div className="text-sm text-gray-500 text-center mt-2">
													{Number(
														complexityMetrics.avgMethodsPerClass
													) > 7
														? "Classes may be too large - consider refactoring"
														: "Good class size"}
												</div>
											</CardContent>
										</Card>

										<Card>
											<CardHeader className="pb-2">
												<CardTitle className="text-base">
													Avg Calls Per Function
												</CardTitle>
											</CardHeader>
											<CardContent>
												<div className="text-3xl font-bold text-center">
													{
														complexityMetrics.avgCallsPerFunction
													}
												</div>
												<div className="text-sm text-gray-500 text-center mt-2">
													{Number(
														complexityMetrics.avgCallsPerFunction
													) > 5
														? "High coupling detected"
														: "Good coupling level"}
												</div>
											</CardContent>
										</Card>

										<Card>
											<CardHeader className="pb-2">
												<CardTitle className="text-base">
													Documentation Coverage
												</CardTitle>
											</CardHeader>
											<CardContent>
												<div className="text-3xl font-bold text-center">
													{
														complexityMetrics.docCoverage
													}
													%
												</div>
												<div className="text-sm text-gray-500 text-center mt-2">
													{Number(
														complexityMetrics.docCoverage
													) < 50
														? "Needs more documentation"
														: "Good documentation level"}
												</div>
											</CardContent>
										</Card>

										<Card>
											<CardHeader className="pb-2">
												<CardTitle className="text-base">
													Suggested Actions
												</CardTitle>
											</CardHeader>
											<CardContent className="text-sm">
												<ul className="list-disc pl-4 space-y-1">
													{Number(
														complexityMetrics.avgMethodsPerClass
													) > 7 && (
														<li>
															Consider splitting
															large classes
														</li>
													)}
													{Number(
														complexityMetrics.avgCallsPerFunction
													) > 5 && (
														<li>
															Reduce coupling
															between components
														</li>
													)}
													{Number(
														complexityMetrics.docCoverage
													) < 50 && (
														<li>
															Add more function
															documentation
														</li>
													)}
													{Number(
														complexityMetrics.docCoverage
													) >= 50 &&
														Number(
															complexityMetrics.avgMethodsPerClass
														) <= 7 &&
														Number(
															complexityMetrics.avgCallsPerFunction
														) <= 5 && (
															<li>
																Good job! Code
																structure looks
																healthy
															</li>
														)}
												</ul>
											</CardContent>
										</Card>
									</div>
								) : (
									<div className="flex items-center justify-center h-full">
										<p className="text-lg text-gray-700 bg-gray-100 p-4 rounded-lg shadow">
											No complexity data available
										</p>
									</div>
								)
							) : (
								<>
									<div
										className="h-full"
										style={{ filter: "blur(4px)" }}
									>
										{complexityMetrics && (
											<div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
												<Card>
													<CardHeader className="pb-2">
														<CardTitle className="text-base">
															Avg Methods Per
															Class
														</CardTitle>
													</CardHeader>
													<CardContent>
														<div className="text-3xl font-bold text-center">
															{
																complexityMetrics.avgMethodsPerClass
															}
														</div>
													</CardContent>
												</Card>
												<Card>
													<CardHeader className="pb-2">
														<CardTitle className="text-base">
															Avg Calls Per
															Function
														</CardTitle>
													</CardHeader>
													<CardContent>
														<div className="text-3xl font-bold text-center">
															{
																complexityMetrics.avgCallsPerFunction
															}
														</div>
													</CardContent>
												</Card>
											</div>
										)}
									</div>
									<div className="absolute inset-0 flex items-center justify-center">
										<div className="bg-black bg-opacity-70 p-4 rounded-lg text-white">
											<Lock
												className="inline mr-2"
												size={20}
											/>
											Upgrade to Plus to access complexity
											metrics
										</div>
									</div>
								</>
							)}
						</div>
					</TabsContent>

					<TabsContent value="summary" className="m-0">
						<div className="h-96 overflow-y-auto p-4 text-white relative">
							{membership >= 3 ? (
								// Real summary generation for members
								isSummaryLoading ? (
									<div className="flex items-center justify-center h-full">
										<div className="flex items-center">
											<div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500 mr-3"></div>
											Generating code summary...
										</div>
									</div>
								) : summary ? (
									<div className="prose prose-invert max-w-none">
										<h3 className="text-xl mb-4">
											Code Summary
										</h3>
										<div
											dangerouslySetInnerHTML={{
												__html: marked.parse(summary),
											}}
										/>
									</div>
								) : (
									<div className="flex items-center justify-center h-full">
										<p className="text-lg bg-gray-800 p-4 rounded-lg">
											Click generate to create a summary
											of your code
										</p>
									</div>
								)
							) : (
								// Dummy blurred summary for non-members
								<>
									<div
										className="h-full prose prose-invert max-w-none"
										style={{ filter: "blur(4px)" }}
									>
										<h3 className="text-xl mb-4">
											Code Summary
										</h3>
										<div
											dangerouslySetInnerHTML={{
												__html: marked.parse(
													dummySummary
												),
											}}
										/>
									</div>
									<div className="absolute inset-0 flex items-center justify-center">
										<div className="bg-black bg-opacity-70 p-4 rounded-lg text-white">
											<Lock
												className="inline mr-2"
												size={20}
											/>
											Upgrade to Plus to access code
											summary
										</div>
									</div>
								</>
							)}
						</div>
					</TabsContent>
				</Tabs>
			</CardContent>
		</Card>
	)
}

export default CodeVisualization
