/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */

/* This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/. */

/* rendering object for CSS "display: flex" */

#ifndef nsFlexContainerFrame_h___
#define nsFlexContainerFrame_h___

#include "nsContainerFrame.h"

namespace mozilla {
template <class T> class LinkedList;
}

nsContainerFrame* NS_NewFlexContainerFrame(nsIPresShell* aPresShell,
                                           nsStyleContext* aContext);

typedef nsContainerFrame nsFlexContainerFrameSuper;

class nsFlexContainerFrame : public nsFlexContainerFrameSuper {
public:
  NS_DECL_FRAMEARENA_HELPERS
  NS_DECL_QUERYFRAME_TARGET(nsFlexContainerFrame)
  NS_DECL_QUERYFRAME

  // Factory method:
  friend nsContainerFrame* NS_NewFlexContainerFrame(nsIPresShell* aPresShell,
                                                    nsStyleContext* aContext);

  // Forward-decls of helper classes
  class FlexItem;
  class FlexLine;
  class FlexboxAxisTracker;
  struct StrutInfo;

  // nsIFrame overrides
  virtual void BuildDisplayList(nsDisplayListBuilder*   aBuilder,
                                const nsRect&           aDirtyRect,
                                const nsDisplayListSet& aLists) MOZ_OVERRIDE;

  virtual void Reflow(nsPresContext*           aPresContext,
                      nsHTMLReflowMetrics&     aDesiredSize,
                      const nsHTMLReflowState& aReflowState,
                      nsReflowStatus&          aStatus) MOZ_OVERRIDE;

  virtual nscoord
    GetMinISize(nsRenderingContext* aRenderingContext) MOZ_OVERRIDE;
  virtual nscoord
    GetPrefISize(nsRenderingContext* aRenderingContext) MOZ_OVERRIDE;

  virtual nsIAtom* GetType() const MOZ_OVERRIDE;
#ifdef DEBUG_FRAME_DUMP
  virtual nsresult GetFrameName(nsAString& aResult) const MOZ_OVERRIDE;
#endif
  // Flexbox-specific public methods
  bool IsHorizontal();

protected:
  // Protected constructor & destructor
  explicit nsFlexContainerFrame(nsStyleContext* aContext) :
    nsFlexContainerFrameSuper(aContext)
  {}
  virtual ~nsFlexContainerFrame();

  /*
   * This method does the bulk of the flex layout, implementing the algorithm
   * described at:
   *   http://dev.w3.org/csswg/css-flexbox/#layout-algorithm
   * (with a few initialization pieces happening in the caller, Reflow().
   *
   * Since this is a helper for Reflow(), this takes all the same parameters
   * as Reflow(), plus a few more parameters that Reflow() sets up for us.
   *
   * (The logic behind the division of work between Reflow and DoFlexLayout is
   * as follows: DoFlexLayout() begins at the step that we have to jump back
   * to, if we find any visibility:collapse children, and Reflow() does
   * everything before that point.)
   */
  void DoFlexLayout(nsPresContext*           aPresContext,
                    nsHTMLReflowMetrics&     aDesiredSize,
                    const nsHTMLReflowState& aReflowState,
                    nsReflowStatus&          aStatus,
                    nscoord aContentBoxMainSize,
                    nscoord aAvailableHeightForContent,
                    nsTArray<StrutInfo>& aStruts,
                    const FlexboxAxisTracker& aAxisTracker);

  /**
   * Checks whether our child-frame list "mFrames" is sorted, using the given
   * IsLessThanOrEqual function, and sorts it if it's not already sorted.
   *
   * XXXdholbert Once we support pagination, we need to make this function
   * check our continuations as well (or wrap it in a function that does).
   *
   * @return true if we had to sort mFrames, false if it was already sorted.
   */
  template<bool IsLessThanOrEqual(nsIFrame*, nsIFrame*)>
  bool SortChildrenIfNeeded();

  // Protected flex-container-specific methods / member-vars
#ifdef DEBUG
  void SanityCheckAnonymousFlexItems() const;
#endif // DEBUG

  /*
   * Returns a new FlexItem for the given child frame, allocated on the heap.
   * Guaranteed to return non-null. Caller is responsible for managing the
   * FlexItem's lifetime.
   *
   * Before returning, this method also processes the FlexItem to resolve its
   * flex basis (including e.g. auto-height) as well as to resolve
   * "min-height:auto", via ResolveAutoFlexBasisAndMinSize(). (Basically, the
   * returned FlexItem will be ready to participate in the "Resolve the
   * Flexible Lengths" step of the Flex Layout Algorithm.)
   */
  FlexItem* GenerateFlexItemForChild(nsPresContext* aPresContext,
                                     nsIFrame* aChildFrame,
                                     const nsHTMLReflowState& aParentReflowState,
                                     const FlexboxAxisTracker& aAxisTracker);

  /**
   * This method performs a "measuring" reflow to get the content height of
   * aFlexItem.Frame() (treating it as if it had auto-height), & returns the
   * resulting height.
   * (Helper for ResolveAutoFlexBasisAndMinSize().)
   */
  nscoord MeasureFlexItemContentHeight(nsPresContext* aPresContext,
                                       FlexItem& aFlexItem,
                                       bool aForceVerticalResizeForMeasuringReflow,
                                       const nsHTMLReflowState& aParentReflowState);

  /**
   * This method resolves an "auto" flex-basis and/or min-main-size value
   * on aFlexItem, if needed.
   * (Helper for GenerateFlexItemForChild().)
   */
  void ResolveAutoFlexBasisAndMinSize(nsPresContext* aPresContext,
                                      FlexItem& aFlexItem,
                                      const nsHTMLReflowState& aItemReflowState,
                                      const FlexboxAxisTracker& aAxisTracker);

  // Creates FlexItems for all of our child frames, arranged in a list of
  // FlexLines.  These are returned by reference in |aLines|. Our actual
  // return value has to be |nsresult|, in case we have to reflow a child
  // to establish its flex base size and that reflow fails.
  void GenerateFlexLines(nsPresContext* aPresContext,
                         const nsHTMLReflowState& aReflowState,
                         nscoord aContentBoxMainSize,
                         nscoord aAvailableHeightForContent,
                         const nsTArray<StrutInfo>& aStruts,
                         const FlexboxAxisTracker& aAxisTracker,
                         mozilla::LinkedList<FlexLine>& aLines);

  nscoord GetMainSizeFromReflowState(const nsHTMLReflowState& aReflowState,
                                     const FlexboxAxisTracker& aAxisTracker);

  nscoord ComputeCrossSize(const nsHTMLReflowState& aReflowState,
                           const FlexboxAxisTracker& aAxisTracker,
                           nscoord aSumLineCrossSizes,
                           nscoord aAvailableHeightForContent,
                           bool* aIsDefinite,
                           nsReflowStatus& aStatus);

  void SizeItemInCrossAxis(nsPresContext* aPresContext,
                           const FlexboxAxisTracker& aAxisTracker,
                           nsHTMLReflowState& aChildReflowState,
                           FlexItem& aItem);

  bool mChildrenHaveBeenReordered; // Have we ever had to reorder our kids
                                   // to satisfy their 'order' values?
};

#endif /* nsFlexContainerFrame_h___ */
