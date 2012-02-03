/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* vim: set sw=2 ts=2 et tw=80 : */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla Content App.
 *
 * The Initial Developer of the Original Code is
 *   The Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Benoit Girard <bgirard@mozilla.com>
 *   Ali Juma <ajuma@mozilla.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "CompositorParent.h"
#include "ShadowLayersParent.h"
#include "LayerManagerOGL.h"
#include "nsIWidget.h"

#if defined(MOZ_WIDGET_ANDROID)
#include "AndroidBridge.h"
#endif

#include <android/log.h>

namespace mozilla {
namespace layers {

CompositorParent::CompositorParent(nsIWidget* aWidget)
  : mStopped(false), mWidget(aWidget)
{
  MOZ_COUNT_CTOR(CompositorParent);
}

CompositorParent::~CompositorParent()
{
  MOZ_COUNT_DTOR(CompositorParent);
}

void
CompositorParent::Destroy()
{
  NS_ABORT_IF_FALSE(ManagedPLayersParent().Length() == 0,
                    "CompositorParent destroyed before managed PLayersParent");

  // Ensure that the layer manager is destroyed on the compositor thread.
  mLayerManager = NULL;
}

bool
CompositorParent::RecvStop()
{
  mStopped = true;
  Destroy();
  return true;
}


void
CompositorParent::ScheduleComposition()
{
  printf_stderr("Schedule composition\n");
  CancelableTask *composeTask = NewRunnableMethod(this, &CompositorParent::Composite);
  MessageLoop::current()->PostTask(FROM_HERE, composeTask);

// Test code for async scrolling.
#ifdef OMTC_TEST_ASYNC_SCROLLING
  static bool scrollScheduled = false;
  if (!scrollScheduled) {
    CancelableTask *composeTask2 = NewRunnableMethod(this,
                                                     &CompositorParent::TestScroll);
    MessageLoop::current()->PostDelayedTask(FROM_HERE, composeTask2, 500);
    scrollScheduled = true;
  }
#endif
}

void
CompositorParent::SetTransformation(float aScale, nsIntPoint aScrollOffset)
{
  mXScale = aScale;
  mYScale = aScale;
  mScrollOffset = aScrollOffset;
}

void
CompositorParent::Composite()
{
  if (mStopped || !mLayerManager) {
    return;
  }

  mLayerManager->EndEmptyTransaction();
}

// Go down shadow layer tree, setting properties to match their non-shadow
// counterparts.
static void
SetShadowProperties(Layer* aLayer)
{
  // FIXME: Bug 717688 -- Do these updates in ShadowLayersParent::RecvUpdate.
  ShadowLayer* shadow = aLayer->AsShadowLayer();
  shadow->SetShadowTransform(aLayer->GetTransform());
  shadow->SetShadowVisibleRegion(aLayer->GetVisibleRegion());
  shadow->SetShadowClipRect(aLayer->GetClipRect());

  for (Layer* child = aLayer->GetFirstChild();
      child; child = child->GetNextSibling()) {
    SetShadowProperties(child);
  }
}

static double GetXScale(const gfx3DMatrix& aTransform)
{
  return aTransform._11;
}

static double GetYScale(const gfx3DMatrix& aTransform)
{
  return aTransform._22;
}

static void ReverseTranslate(gfx3DMatrix& aTransform, ViewTransform& aViewTransform)
{
  aTransform._41 -= aViewTransform.mTranslation.x / aViewTransform.mXScale;
  aTransform._42 -= aViewTransform.mTranslation.y / aViewTransform.mYScale;
}

void
CompositorParent::TransformShadowTree(Layer* aLayer, const ViewTransform& aTransform,
                    float aTempScaleDiffX, float aTempScaleDiffY)
{
  ShadowLayer* shadow = aLayer->AsShadowLayer();

  gfx3DMatrix shadowTransform = aLayer->GetTransform();
  ViewTransform layerTransform = aTransform;

  ContainerLayer* container = aLayer->AsContainerLayer();

  if (container && container->GetFrameMetrics().IsScrollable()) {
    const FrameMetrics* metrics = &container->GetFrameMetrics();
    const gfx3DMatrix& currentTransform = aLayer->GetTransform();

    aTempScaleDiffX *= GetXScale(shadowTransform);
    aTempScaleDiffY *= GetYScale(shadowTransform);

    nsIntPoint metricsScrollOffset = metrics->mViewportScrollOffset;

    nsIntPoint scrollCompensation(
        (mScrollOffset.x / aTempScaleDiffX - metricsScrollOffset.x) * mXScale,
        (mScrollOffset.y / aTempScaleDiffY - metricsScrollOffset.y) * mYScale);
    ViewTransform treeTransform(-scrollCompensation, mXScale,
                                mYScale);
    shadowTransform = gfx3DMatrix(treeTransform) * currentTransform;
    layerTransform = treeTransform;
  }

  // Uncomment to deal with position:fixed.
  /*
  if (aLayer->GetIsFixedPosition() &&
      !aLayer->GetParent()->GetIsFixedPosition()) {
    printf_stderr("Correcting for position fixed\n");
    ReverseTranslate(shadowTransform, layerTransform);
    const nsIntRect* clipRect = shadow->GetShadowClipRect();
    if (clipRect) {
      nsIntRect transformedClipRect(*clipRect);
      transformedClipRect.MoveBy(shadowTransform._41, shadowTransform._42);
      shadow->SetShadowClipRect(&transformedClipRect);
    }
  }*/

  shadow->SetShadowTransform(shadowTransform);

  // Uncomment the following when we want to deal with position:fixed.
  // Note that we need to modify other code to ensure that position:fixed
  // things get their own layer. See Bug 607417.
  /*
  for (Layer* child = aLayer->GetFirstChild(); child;
       child = child->GetNextSibling()) {
    TransformShadowTree(child, layerTransform, aTempScaleDiffX,
                       aTempScaleDiffY);
  }*/

}

void
CompositorParent::AsyncRender()
{
  if (mStopped || !mLayerManager) {
    return;
  }

  Layer* root = mLayerManager->GetRoot();
  ContainerLayer* container = root->AsContainerLayer();
  if (!container)
    return;

  FrameMetrics metrics = container->GetFrameMetrics();
/*
    printf("FrameMetrics: mViewPort: X: %d, Y: %d, Width: %d, Height: %d ",
            metrics.mViewport.X(), metrics.mViewport.Y(), metrics.mViewport.Width(),
            metrics.mViewport.Height());
    printf("mDisplayPort: X: %d, Y: %d, Width: %d, Height: %d ",
            metrics.mDisplayPort.X(), metrics.mDisplayPort.Y(), metrics.mDisplayPort.Width(),
            metrics.mDisplayPort.Height());
    printf("mContentSize: width: %d, height: %d ", metrics.mContentSize.width,
           metrics. mContentSize.height);
    printf("mViewPortScrollOffset: x: %d, y: %d\n",
            metrics.mViewportScrollOffset.x,
            metrics.mViewportScrollOffset.y);
*/
    // Modify framemetrics here, just as a test.
  metrics.mScrollId = FrameMetrics::ROOT_SCROLL_ID;
  container->SetFrameMetrics(metrics);
  ViewTransform transform;
  TransformShadowTree(root, transform);
  Composite();
}

void
CompositorParent::ShadowLayersUpdated()
{
  printf_stderr("ShadowLayersUpdated\n");
  const nsTArray<PLayersParent*>& shadowParents = ManagedPLayersParent();
  NS_ABORT_IF_FALSE(shadowParents.Length() <= 1,
                    "can only support at most 1 ShadowLayersParent");
  if (shadowParents.Length()) {
    Layer* root = static_cast<ShadowLayersParent*>(shadowParents[0])->GetRoot();
    mLayerManager->SetRoot(root);
    SetShadowProperties(root);
  }
  ScheduleComposition();
}

// Test code for async scrolling.
#ifdef OMTC_TEST_ASYNC_SCROLLING
void
CompositorParent::TestScroll()
{
  static int scrollFactor = 0;
  static bool fakeScrollDownwards = true;
  if (fakeScrollDownwards) {
    scrollFactor++;
    if (scrollFactor > 10) {
      scrollFactor = 10;
      fakeScrollDownwards = false;
    }
  } else {
    scrollFactor--;
    if (scrollFactor < 0) {
      scrollFactor = 0;
      fakeScrollDownwards = true;
    }
  }
  SetTransformation(1.0+2.0*scrollFactor/10, nsIntPoint(-25*scrollFactor,
      -25*scrollFactor));
  printf_stderr("AsyncRender scroll factor:%d\n", scrollFactor);
  AsyncRender();

  CancelableTask *composeTask = NewRunnableMethod(this, &CompositorParent::TestScroll);
  MessageLoop::current()->PostDelayedTask(FROM_HERE, composeTask, 1000/65);
}
#endif

PLayersParent*
CompositorParent::AllocPLayers(const LayersBackend &backendType)
{
#ifdef MOZ_WIDGET_ANDROID
  // Registering with the compositor will create the surface view that
  // the layer manager expects to attach to.
  //RegisterCompositorWithJava();
#endif

  if (backendType == LayerManager::LAYERS_OPENGL) {
    nsRefPtr<LayerManagerOGL> layerManager = new LayerManagerOGL(mWidget);
    mWidget = NULL;
    mLayerManager = layerManager;

    if (!layerManager->Initialize()) {
      NS_ERROR("Failed to init OGL Layers");
      return NULL;
    }

    ShadowLayerManager* slm = layerManager->AsShadowManager();
    if (!slm) {
      return NULL;
    }
    return new ShadowLayersParent(slm, this);
  } else {
    NS_ERROR("Unsupported backend selected for Async Compositor");
    return NULL;
  }
}

bool
CompositorParent::DeallocPLayers(PLayersParent* actor)
{
  delete actor;
  return true;
}

#ifdef MOZ_WIDGET_ANDROID
void
CompositorParent::RegisterCompositorWithJava()
{
  mozilla::AndroidBridge::Bridge()->RegisterCompositor();
}
#endif

} // namespace layers
} // namespace mozilla

